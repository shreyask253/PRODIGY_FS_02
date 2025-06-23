
# Flask Employee Management App

This is a simple Flask-based web application for managing employee records. It includes authentication, CRUD functionality, and a clean UI with custom CSS styling.

## 🌟 Features

- User Login (admin only)
- Add, Edit, Delete Employee Records
- Dashboard View
- Styled with custom CSS
- SQLite Database using SQLAlchemy

## 🔧 Technologies Used

- Python
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- HTML/CSS

## 🚀 How to Run Locally

### 1. Install Dependencies

```bash
pip install flask flask_sqlalchemy flask_login flask_wtf wtforms
```

### 2. Unzip and Navigate

```bash
unzip employee_app_styled.zip
cd employee_app
```

### 3. Run the App

```bash
python app.py
```

Visit [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

### 🧪 Default Admin Login

- **Username**: `admin`
- **Password**: `admin`

## 📁 Project Structure

```
employee_app/
├── app.py
├── static/
│   └── style.css
├── templates/
│   ├── login.html
│   ├── dashboard.html
│   └── employee_form.html
└── README.md
```

## 📦 Deployment

You can deploy this app to:

- **Render**: [https://render.com](https://render.com)
- **Railway**: [https://railway.app](https://railway.app)

## ✅ License

This project is open-source and free to use.
