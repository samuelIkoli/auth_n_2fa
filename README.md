# auth_n_2fa

Simple authentication service with 2fa with time-based OTP and authentication app

## 📁 Project Configuration

The project is divided into:

- Controllers: found in `src/controller` folder. The functions that get executed when the endpoints are called is defined here.

- Routes: found in `src/routes` directory. URL endpoints and their corresponding method/action.

- Interfaces: found in `src/interfaces` directory. To ensure type matching from user input.

- Utils: found in `src/utils` directory. Helper functions that may be called at multiple points in the application.

## Getting Started: Running the Server

### 🔧 Tech Stack

- NodeJS
- ExpressJS
- Typescript
- MySQL
- KnexJS

### 📝 Requirements

This project requires nodeJS version >= 14 and npm package manager.

### 💻 Running Locally

1. Clone this repository by running:
   ```bash
   git clone git@github.com:samuelIkoli/auth_n_2fa.git
   cd auth_n_2fa
   ```
2. Install the dependencies:
   ```bash
   npm install
   ```
3. Start the server in dev mode:
   ```bash
   npm run dev
   ```

### 💻 Testing

Online API testing tools such as **Postman** and **Thunderclient** can be used to test the endpoints. Testing can be carried out on the postman documentation endpoint [here](https://www.postman.com/crimson-capsule-415986/workspace/new-team-workspace/collection/19177553-73086e59-b7aa-4fbb-bbd2-951d38a0f556?action=share&creator=19177553).

## 📖 Documentation

Documentation can be found [here](https://www.postman.com/crimson-capsule-415986/workspace/new-team-workspace/collection/19177553-73086e59-b7aa-4fbb-bbd2-951d38a0f556?action=share&creator=19177553)

## 🔗 Link(s)

- [You can interact with the frontend of this project here](reactauth-iota.vercel.app)

Built by SAMUEL IKOLI
