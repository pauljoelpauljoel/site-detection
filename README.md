# Scam Site Detection Web App

A machine learning-powered web application to detect safe, suspicious, and scam websites based on URL features. Built with Flask, HTML/CSS/JS, and Scikit-Learn.

## Features
- **Real-time Detection**: Predicts if a site is Safe, Suspicious, or a Scam instantly.
- **Responsive Design**: Works on Mobile, Tablet, and Desktop.
- **Machine Learning**: Uses a Random Forest classifier trained on URL features.
- **Confidence Score**: Shows the probability of the prediction.

## Project Structure
- `app.py`: Main Flask application.
- `train_model.py`: Script to train and save the ML model (`model.pkl`).
- `templates/index.html`: Frontend HTML.
- `static/style.css`: Responsive styling.
- `static/script.js`: Frontend logic (AJAX).
- `requirements.txt`: Python dependencies.
- `Procfile`: Configuration for Render deployment.

## How to Run Locally

1.  **Install Python**: Ensure Python 3.x is installed.
2.  **Create a Virtual Environment** (Optional but recommended):
    ```bash
    python -m venv venv
    # Windows
    venv\Scripts\activate
    # Mac/Linux
    source venv/bin/activate
    ```
3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
4.  **Train the Model**:
    ```bash
    python train_model.py
    ```
    This generates the `model.pkl` file.
5.  **Run the App**:
    ```bash
    python app.py
    ```
6.  **Open in Browser**:
    Go to `http://127.0.0.1:5000`

## How to Deploy on Render

1.  Push this code to a GitHub repository.
2.  Log in to [Render](https://render.com/).
3.  Click **New +** -> **Web Service**.
4.  Connect your GitHub repository.
5.  Render will auto-detect the `requirements.txt` and `Procfile`.
6.  Click **Create Web Service**.
7.  Your app will be live in a few minutes!
