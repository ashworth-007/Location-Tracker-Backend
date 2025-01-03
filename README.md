
### Backend `README.md`

```markdown
# Live Location Tracker - Backend

This is the backend of the Live Location Tracker application, built using Node.js, Express, MongoDB, and JWT for authentication. It handles user registration, login, and location tracking.

## Features
- User registration and login with JWT authentication
- Tracks user location every 4 seconds and stores it in the MongoDB database
- Admin dashboard to view all registered users and their location logs
- Scalable backend to handle multiple users in real-time

## Prerequisites
- Node.js (v16 or above)
- npm (v8 or above)
- MongoDB (either local or MongoDB Atlas)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/live-location-tracker-backend.git
   cd live-location-tracker-backend

2.Install dependencies:
npm install

3.Create a .env file in the root directory with the following content:
MONGO_URI=your-mongo-db-connection-string
JWT_SECRET=your-secret-key

4.Start the server:
npm start
