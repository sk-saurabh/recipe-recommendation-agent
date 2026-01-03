"""Flask web application for Recipe Bot chat interface."""
import json
import os
import re
import uuid
import urllib.parse
import boto3
import requests
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from boto3.session import Session
from functools import wraps


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Configuration
AGENT_ARN = "arn:aws:bedrock-agentcore:us-west-2:472284507901:runtime/recipeBot_Agent-EroI2I9lpN"
REGION_NAME = "us-west-2"
COGNITO_CLIENT_ID = os.environ.get('COGNITO_CLIENT_ID', '5j26urvknbp1bqr8avutfs46qv')

# Initialize AWS clients
agent_core_client = boto3.client('bedrock-agentcore')
cognito_client = boto3.client('cognito-idp', region_name=REGION_NAME)

def login_required(f):
    """Decorator to require user login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def authenticate_user_cognito(username, password):
    """Authenticate user with Cognito and get access token."""
    try:
        auth_response = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
        
        bearer_token = auth_response["AuthenticationResult"]["AccessToken"]
        
        # Get user attributes
        user_response = cognito_client.get_user(AccessToken=bearer_token)
        user_attributes = {attr['Name']: attr['Value'] for attr in user_response['UserAttributes']}
        
        return {
            'bearer_token': bearer_token,
            'username': user_response['Username'],
            'email': user_attributes.get('email', ''),
            'user_id': user_attributes.get('sub', '')
        }
    except Exception as e:
        print(f"Authentication failed: {str(e)}")
        return None


def register_user_cognito(username, email, password):
    """Register a new user with Cognito."""
    try:
        response = cognito_client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=username,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email}
            ]
        )
        return response
    except Exception as e:
        print(f"Registration failed: {str(e)}")
        return None


def reauthenticate_user(client_id):
    """Authenticate user and get access token from Cognito."""
    print(f"DEBUG: Starting authentication with client_id: {client_id}", flush=True)
    
    boto_session = Session()
    region = boto_session.region_name
    print(f"DEBUG: Using region: {region}", flush=True)
    
    # Initialize Cognito client
    cognito_auth_client = boto3.client("cognito-idp", region_name=region)
    print("DEBUG: Cognito client initialized", flush=True)
    
    # Get user credentials from session
    if 'username' not in session or 'password' not in session:
        raise ValueError("User credentials not found in session")
    
    username = session['username']
    password = session['password']
    
    # Authenticate User and get Access Token
    print(f"DEBUG: Attempting auth with USERNAME: {username}", flush=True)
    try:
        auth_response = cognito_auth_client.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
        print("DEBUG: auth_response received: ", auth_response, flush=True)
        
        bearer_token = auth_response["AuthenticationResult"]["AccessToken"]
        print(f"DEBUG: Bearer token extracted (length: {len(bearer_token)})", flush=True)
        return bearer_token
    except Exception as e:
        print(f"DEBUG: Authentication failed with error: {str(e)}", flush=True)
        print(f"DEBUG: Error type: {type(e).__name__}", flush=True)
        raise ValueError(f"Authentication failed: {str(e)}")

def invoke_recipe_agent(prompt, session_id=None, bearer_token="", username=None):
    """Invoke the recipe agent with the given prompt using HTTP requests."""
    if session_id is None:
        session_id = str(uuid.uuid4())
    
    try:
        # URL encode the agent ARN
        escaped_agent_arn = urllib.parse.quote(AGENT_ARN, safe='')
        
        # Construct the URL
        url = f"https://bedrock-agentcore.{REGION_NAME}.amazonaws.com/runtimes/{escaped_agent_arn}/invocations?qualifier=DEFAULT"
        
        # Set up headers
        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "X-Amzn-Trace-Id": f"trace-id-{uuid.uuid4()}",
            "Content-Type": "application/json",
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
            "X-Amzn-Bedrock-AgentCore-Runtime-Custom-User-Id": username
        }
        
        # Make the HTTP request
        response = requests.post(
            url,
            headers=headers,
            data=json.dumps({"prompt": prompt}),
            timeout=30
        )
        
        # Handle response based on status code
        if response.status_code == 200:
            return response.json()
        if response.status_code >= 400:
            error_data = response.json()
            return {"error": f"Agent invocation failed ({response.status_code}): {error_data}"}
        return {"error": f"Unexpected status code: {response.status_code}"}
            
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Failed to invoke agent: {str(e)}"}


def format_response_text(response_text):
    """Format the response text for better readability."""
    if not response_text or not isinstance(response_text, str):
        return response_text
    
    # Split into sentences and paragraphs
    formatted_text = response_text.replace('**', '')  # Remove markdown bold
    
    # Add line breaks after questions and before numbered lists
    formatted_text = formatted_text.replace('?**', '?\n\n')
    formatted_text = formatted_text.replace('? **', '?\n\n')
    formatted_text = formatted_text.replace(') ', ')\n')
    
    # Format numbered lists
    formatted_text = re.sub(r'(\d+\.\s)', r'\n\1', formatted_text)
    
    # Clean up extra spaces and normalize line breaks
    formatted_text = re.sub(r'\s+', ' ', formatted_text)
    formatted_text = re.sub(r'\n\s*\n', '\n\n', formatted_text)
    
    # Add proper spacing around key phrases
    formatted_text = formatted_text.replace(
        'To give you the best suggestions, I need to know',
        '\n\nTo give you the best suggestions, I need to know'
    )
    formatted_text = formatted_text.replace(
        'Once you share these details',
        '\n\nOnce you share these details'
    )
    
    return formatted_text.strip()


@app.route('/')
@login_required
def index():
    """Render the main chat interface."""
    current_user = {
        'username': session.get('username', 'User'),
        'email': session.get('email', '')
    }
    return render_template('index.html', current_user=current_user)


@app.route('/welcome')
def welcome():
    """Welcome page that redirects to login or chat based on auth status."""
    if 'user_id' in session:
        return redirect(url_for('index'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = authenticate_user_cognito(username, password)
        
        if user_data:
            # Store user data in session
            session['user_id'] = user_data['user_id']
            session['username'] = user_data['username']
            session['email'] = user_data['email']
            session['bearer_token'] = user_data['bearer_token']
            session['password'] = password  # Store for re-authentication
            
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validate passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        # Validate password strength (Cognito requirements)
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('register.html')

        # Check for required character types
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one uppercase letter', 'error')
            return render_template('register.html')
        if not re.search(r'[a-z]', password):
            flash('Password must contain at least one lowercase letter', 'error')
            return render_template('register.html')
        if not re.search(r'\d', password):
            flash('Password must contain at least one number', 'error')
            return render_template('register.html')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            flash('Password must contain at least one special character', 'error')
            return render_template('register.html')
        
        # Register user with Cognito
        result = register_user_cognito(username, email, password)
        
        if result:
            flash('Registration successful! Please check your email for verification.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. Username or email may already exist.', 'error')
    
    return render_template('register.html')


@app.route('/logout')
def logout():
    """Handle user logout."""
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))


@app.route('/chat', methods=['POST'])
@login_required
def chat():
    """Handle chat messages from the user."""
    data = request.get_json()
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({"error": "No message provided"}), 400
    
    # Get or create session ID and bearer token
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    
    # Get or create bearer token (only authenticate if we don't have a token)
    if 'bearer_token' not in session:
        try:
            session['bearer_token'] = reauthenticate_user(COGNITO_CLIENT_ID)
        except Exception as e:
            return jsonify({"error": f"Authentication failed: {str(e)}"}), 401
    
    session_id = session['session_id']
    bearer_token = session['bearer_token']
    user_name = session['username']
    # Invoke the recipe agent
    response = invoke_recipe_agent(user_message, session_id, bearer_token, user_name)
    
    # If we get an authentication error, try to re-authenticate once
    if isinstance(response, dict) and 'error' in response:
        error_msg = response['error'].lower()
        if 'unauthorized' in error_msg or 'token' in error_msg or 'auth' in error_msg:
            try:
                # Re-authenticate and try again
                session['bearer_token'] = reauthenticate_user(COGNITO_CLIENT_ID)
                bearer_token = session['bearer_token']
                response = invoke_recipe_agent(user_message, session_id, bearer_token)
            except Exception as e:
                return jsonify({"error": f"Re-authentication failed: {str(e)}"}), 401
    
    # Format the response for better display
    if isinstance(response, str):
        formatted_response = format_response_text(response)
    elif isinstance(response, dict) and 'error' not in response:
        # If response is a dict, try to extract the main content
        formatted_response = format_response_text(str(response))
    else:
        formatted_response = response
    
    return jsonify({
        "response": formatted_response,
        "session_id": session_id
    })


@app.route('/new_session', methods=['POST'])
@login_required
def new_session():
    """Start a new chat session and clear stored tokens."""
    # Clear both session ID and bearer token to force re-authentication
    session['session_id'] = str(uuid.uuid4())
    if 'bearer_token' in session:
        del session['bearer_token']

    bearer_token = reauthenticate_user(COGNITO_CLIENT_ID)
    session['bearer_token'] = bearer_token
    
    return jsonify({
        "message": "New session started", 
        "session_id": session['session_id'],
        "bearer_token": bearer_token
    })


if __name__ == '__main__':
    # Enable detailed error logging
    import logging
    logging.basicConfig(level=logging.DEBUG)

    # Run with debug mode and automatic reloader
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=True, use_debugger=True)