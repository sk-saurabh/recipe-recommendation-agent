# Recipe Bot Web Application

A Flask web application that provides a chat interface for the Recipe Bot with user authentication via AWS Cognito.

## Features

- **User Authentication**: Sign up and sign in using AWS Cognito User Pool
- **Chat Interface**: Interactive chat with the Recipe Bot agent
- **Session Management**: Persistent chat sessions per user
- **Responsive Design**: Mobile-friendly interface
- **Real-time Communication**: Direct integration with Bedrock AgentCore
- **Error Handling**: Graceful error handling and user feedback

## Setup

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Environment Variables**:
   Set the following environment variables:
   ```bash
   export SECRET_KEY="your-flask-secret-key"
   export COGNITO_CLIENT_ID="your-cognito-client-id"
   ```

3. **AWS Configuration**:
   Ensure your AWS credentials are configured for the us-west-2 region:
   ```bash
   aws configure
   ```

## Authentication Flow

1. **Sign Up**: New users can create accounts via `/register`
2. **Sign In**: Existing users authenticate via `/login`
3. **Chat Access**: Authenticated users can access the chat interface at `/`
4. **Logout**: Users can logout via the logout button in the chat interface

## Cognito Integration

The application integrates with AWS Cognito for:
- User registration with email verification
- User authentication and token management
- Secure session handling
- Password policy enforcement (8+ chars, uppercase, lowercase, number, special char)

## API Endpoints

- `GET /` - Main chat interface (requires authentication)
- `GET /login` - Login page
- `POST /login` - Handle login form submission
- `GET /register` - Registration page
- `POST /register` - Handle registration form submission
- `GET /logout` - Logout and clear session
- `POST /chat` - Send message to Recipe Bot (requires authentication)
- `POST /new_session` - Start new chat session (requires authentication)

## Running the Application

```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Testing

Run the authentication test:
```bash
python test_auth.py
```

## Usage

1. Navigate to `http://localhost:5000`
2. Sign up for a new account or sign in with existing credentials
3. Start chatting with the Recipe Bot about ingredients, recipes, and cooking suggestions
4. Use "New Session" to start fresh conversations
5. Logout when finished

## Architecture

The web app integrates Cognito authentication with the existing agent invocation:
- User authentication via AWS Cognito User Pool
- Session-based user management with Flask sessions
- Direct communication with Bedrock AgentCore using user-specific tokens
- Responsive web interface with real-time chat functionality