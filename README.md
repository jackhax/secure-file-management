# Secure File Management System

This is a secure file management system built using Python, Flask, and SQLite. It allows users to register, log in, upload files, download files, and share files with other users. The application also includes an admin portal for managing users and files.

## Features

- User registration and login
- File upload and download
- File sharing between users
- Admin portal for managing users and files
- Secure file access with user authentication
- Minimalistic and responsive UI using Bootstrap

## Technologies Used

- Python
- Flask
- SQLite
- Bootstrap

## Getting Started

Follow these instructions to set up and run the project locally on your machine.

### Prerequisites

- Python 3.x
- Virtualenv (optional but recommended)

### Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/mayank-ramnani/secure-file-management.git
   cd secure-file-management
   ```

2. **Set Up a Virtual Environment**

   It's recommended to use a virtual environment to manage dependencies.

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies**

   Install the required Python packages using pip.

   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the Database**

   Run the database initialization script to create the necessary tables.

   ```bash
   python init_db.py
   ```

5. **Run the Application**

   Start the Flask development server.

   ```bash
   python run.py
   ```

6. **Access the Application**

   Open your web browser and go to `http://127.0.0.1:5000/` to access the application.

### Project Structure

- `app/`: Contains the main application code.
  - `__init__.py`: Initializes the Flask app and configures extensions.
  - `models.py`: Defines the database models.
  - `routes.py`: Contains the application routes and logic.
  - `templates/`: Contains HTML templates for the application.
  - `static/`: Contains static files like CSS and JavaScript.

- `uploads/`: Directory where uploaded files are stored.

- `venv/`: Virtual environment directory (not included in the repository).

- `run.py`: Entry point for running the application.

- `init_db.py`: Script to initialize the database.

### Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or bug fixes.

### License

This project is licensed under the MIT License.

