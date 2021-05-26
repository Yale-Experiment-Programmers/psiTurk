from __future__ import generator_stop
from flask import Blueprint, render_template, request, current_app as app, \
    flash, session, g, redirect, url_for, jsonify
from flask_login import login_user, logout_user, current_user
from functools import wraps
from psiturk.psiturk_config import PsiturkConfig
from psiturk.user_utils import PsiTurkAuthorization, nocache
from psiturk.psiturk_exceptions import *
from psiturk.amt_services_wrapper import WrapperResponseSuccess, WrapperResponseError

from psiturk.services_manager import SESSION_SERVICES_MANAGER_MODE_KEY, \
    psiturk_services_manager as services_manager
from flask_login import LoginManager, UserMixin

# # Database setup
from psiturk.models import Participant, Hit

# load the configuration options
config = PsiturkConfig()
config.load_config()

# if you want to add a password protect route use this
myauth = PsiTurkAuthorization(config)

# import the Blueprint
dashboard = Blueprint('dashboard', __name__,
                      template_folder='templates',
                      static_folder='static', url_prefix='/dashboard')


# ---------------------------------------------------------------------------- #
#                                   Constants                                  #
# ---------------------------------------------------------------------------- #

# PsiTurk HIT status codes
PSITURK_STATUS_CODES = [
    'Not Accepted',
    'Allocated',
    'Started',
    'Completed',
    'Submitted',
    'Approved',
    'Quit Early',
    'Bonused'
]

# ---------------------------------------------------------------------------- #
#                                     LOGIN                                    #
# ---------------------------------------------------------------------------- #

login_manager = LoginManager()
login_manager.login_view = 'dashboard.login'


# Initializes app with a services wrapper if not unit testing
def init_app(app):
    if not app.config.get('LOGIN_DISABLED'):
        # this dashboard requires a valid mturk connection -- try for one here
        try:
            _ = services_manager.amt_services_wrapper  # may throw error if aws keys not set
        except NoMturkConnectionError:
            raise Exception((
                'Dashboard requested, but no valid mturk credentials found. '
                'Either disable the dashboard in config, or set valid mturk credentials -- '
                'see https://psiturk.readthedocs.io/en/latest/amt_setup.html#aws-credentials . '
                '\nRefusing to start.'
                ))
    login_manager.init_app(app)


# Flask User model
class DashboardUser(UserMixin):
    def __init__(self, username=''):
        self.id = username


# Gets the Flask User from a username
@login_manager.user_loader
def load_user(username):
    return DashboardUser(username=username)

def is_static_resource_call():
    return str(request.endpoint) == 'dashboard.static'

def is_login_route():
    return str(request.url_rule) == '/dashboard/login'

# Wrapper to require a login for a view
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if current_user.is_authenticated:
            pass
        elif app.config.get('LOGIN_DISABLED'):  # for unit testing
            pass
        elif is_static_resource_call() or is_login_route():
            pass
        else:
            return login_manager.unauthorized()
        return view(*args, **kwargs)

    return wrapped_view


# ---------------------------------------------------------------------------- #
#                                 AMT SERVICES                                 #
# ---------------------------------------------------------------------------- #

# Wrapper to initialize an AMT services for a view
def try_amt_services_wrapper(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        try:
            _ = services_manager.amt_services_wrapper  # may throw error if aws keys not set
            if SESSION_SERVICES_MANAGER_MODE_KEY not in session:
                app.logger.debug('setting session mode to {}'.format(services_manager.mode))
                session[SESSION_SERVICES_MANAGER_MODE_KEY] = services_manager.mode
            else:
                app.logger.debug(
                    'found session mode: {}'.format(session[SESSION_SERVICES_MANAGER_MODE_KEY]))
                services_manager.mode = session[SESSION_SERVICES_MANAGER_MODE_KEY]
                app.logger.debug('I set services manager mode to {}'.format(services_manager.mode))
            return view(**kwargs)
        except Exception as e:
            if not is_login_route() and not is_static_resource_call():
                message = e.message if hasattr(e, 'message') else str(e)
                flash(message, 'danger')

                return redirect(url_for('.login'))

    return wrapped_view

# ---------------------------------------------------------------------------- #
#                               DASHBOARD ROUTES                               #
# ---------------------------------------------------------------------------- #

# Before all requests in the dashboard, check for login and AMT services
@dashboard.before_request
@login_required
@try_amt_services_wrapper
def before_request():
    pass

# Changes the mode of the AMT services object between live and sandbox
@dashboard.route('/mode', methods=('GET', 'POST'))
def mode():
    if request.method == 'POST':
        mode = request.form['mode']
        if mode not in ['live', 'sandbox']:
            flash('unrecognized mode: {}'.format(mode), 'danger')
        else:
            try:
                services_manager.mode = mode
                session[SESSION_SERVICES_MANAGER_MODE_KEY] = mode
                flash('mode successfully updated to {}'.format(mode), 'success')
            except Exception as e:
                flash(str(e), 'danger')
    mode = services_manager.mode
    return render_template('dashboard/mode.html', mode=mode)

# Home page of the dashboard
@dashboard.route('/index')
@dashboard.route('/')
def index():
    current_codeversion = config['Task Parameters']['experiment_code_version']
    return render_template('dashboard/index.html',
                           current_codeversion=current_codeversion)

# List of the HITs connected to the account
@dashboard.route('/hits')
@dashboard.route('/hits/')
@dashboard.route('/hits/<hit_id>')
@dashboard.route('/hits/<hit_id>/')
def hits_list(hit_id=None):
    return render_template('dashboard/hits/list.html', hit_id=hit_id)

# List of the assignments connected to an HIT
@dashboard.route('/hits/<hit_id>/assignments')
@dashboard.route('/hits/<hit_id>/assignments/')
def assignments_list(hit_id):
    return render_template('dashboard/assignments/list.html', hit_id=hit_id)

# Login route
@dashboard.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            if not myauth.check_auth(username, password):
                raise Exception('Incorrect username or password')

            user = DashboardUser(username=username)
            login_user(user)
            # flash("Logged in successfully.")
            next = request.args.get('next', None)
            return redirect(next or url_for('.index'))
        except Exception as e:
            pass
            # flash(str(e), 'danger')
    
    return render_template('dashboard/login.html')

# Logout route
@dashboard.route('/logout')
def logout():
    logout_user()
    # flash('Logged out successfully.')
    return redirect(url_for('.login'))


# ---------------------------------------------------------------------------- #
#                                      API                                     #
# ---------------------------------------------------------------------------- #

# Wrapper for API responses, which should always be WrapperResponseSuccess or 
# WrapperResponseError objects. If they are not, return a 400.
def api_response(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            response = func(*args, **kwargs)
            if isinstance(response, WrapperResponseSuccess):
                return jsonify(
                    response.to_dict()), 200
            if isinstance(response, dict) and 'exception' in response:
                return jsonify(
                    WrapperResponseError(
                        operation=func.__name__,
                        exception=str(response.pop('exception')), data=response
                    ).to_dict()), 400
            return jsonify(WrapperResponseSuccess(
                operation=func.__name__, data=response).to_dict()), 200
        except Exception as e:
            return jsonify(WrapperResponseError(
                operation=func.__name__, exception=str(e))), 400
    return wrapper


# Gets all HITs from MTurk, adding a field which denotes whether a HIT is present in the
# local PsiTurk database or not. Fields:
#  - local: limits results to only local HITs
#  - statuses: HIT statuses to filter for
@dashboard.route('/api/hits', methods=['POST'])
@api_response
def api_hits():
    local = request.json['local']
    statuses = request.json['statuses']

    all_hits = services_manager.amt_services_wrapper.amt_services.get_all_hits().data
    my_hit_ids = list(set([hit.hitid for hit in Hit.query.distinct(Hit.hitid)]))
    hits = map(lambda hit: dict(hit.options, is_local=hit.options['hitid'] in my_hit_ids), all_hits)

    if local:
        hits = [hit for hit in hits if hit['is_local']]
    if len(statuses) > 0:
        hits = list(filter(lambda hit: hit['status'] in statuses, hits))

    return hits


# Creates an HIT through MTurk with the specified inputs


# Gets all assignments from MTurk for a specific HIT
#  - hitids: the ids of the HITs to query assignments from
#  - local: query assignments from PsiTurk DB over MTurk?
#  - statuses: assignment statuses to filter for
@dashboard.route('/api/assignments', methods=['POST'])
@api_response
def api_assignments():
    hitids = request.json['hitids']
    local = request.json['local']
    statuses = request.json['statuses']

    if local:
        statuses = map(lambda status: PSITURK_STATUS_CODES.index(status), statuses)
        participantquery = Participant.query \
            .filter(Participant.hitid.in_(hitids)) \
                .filter(Participant.status.in_(statuses)).all()
        assignments = [p.to_dict() for p in participantquery]
    else:
        assignments = services_manager.amt_services_wrapper.amt_services \
            .get_assignments(assignment_statuses=statuses, hit_ids=hitids).data

    return assignments


