from flask import Flask, request, redirect, render_template_string, session, url_for
import boto3
import logging
from werkzeug.utils import secure_filename

# =========================
# CONFIG
# =========================
APP_USERNAME = "TA2"
APP_PASSWORD = "cloudproject"

S3_BUCKET = "cloud-project-ta2"
S3_FOLDER = "uploads/"

AWS_REGION = "ap-south-1"

# =========================
# INIT
# =========================
app = Flask(__name__)
app.secret_key = "supersecretkey"

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# S3 Client
s3 = boto3.client("s3", region_name=AWS_REGION)

# =========================
# HTML TEMPLATES
# =========================

login_page = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login</title>
    <style>
        body {
            font-family: Arial;
            background: #0f172a;
            color: white;
            text-align: center;
        }

        .box {
            margin-top: 100px;
        }

        input {
            padding: 10px;
            margin: 10px;
            width: 250px;
        }

        button {
            padding: 10px 20px;
            background: #22c55e;
            border: none;
            color: white;
            cursor: pointer;
        }
    </style>
</head>
<body>

<div class="box">
    <h2>Secure Upload Portal</h2>

    <form method="POST">
        <input type="text" name="username" placeholder="Username"><br>

        <input type="password" name="password" placeholder="Password"><br>

        <button type="submit">Login</button>
    </form>
</div>

</body>
</html>
"""

upload_page = """
<!DOCTYPE html>
<html>
<head>
    <title>Upload</title>
    <style>
        body {
            font-family: Arial;
            background: #020617;
            color: white;
            text-align: center;
        }

        .box {
            margin-top: 100px;
        }

        input {
            padding: 10px;
            margin: 10px;
        }

        button {
            padding: 10px 20px;
            background: #3b82f6;
            border: none;
            color: white;
            cursor: pointer;
        }
    </style>
</head>
<body>

<div class="box">
    <h2>Upload File</h2>

    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file"><br>

        <button type="submit">Upload</button>
    </form>

    <br>

    <a href="/logout" style="color:red;">Logout</a>
</div>

</body>
</html>
"""

# =========================
# ROUTES
# =========================

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        logger.info(
            f"Login attempt → Username: {username}, IP: {request.remote_addr}"
        )

        if username == APP_USERNAME and password == APP_PASSWORD:

            session["logged_in"] = True

            logger.info(f"Successful login → {username}")

            return redirect(url_for("upload"))

        else:
            logger.warning(f"Failed login → {username}")

            return "Invalid credentials", 401

    return render_template_string(login_page)


@app.route("/upload", methods=["GET", "POST"])
def upload():

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if request.method == "POST":

        if "file" not in request.files:
            return "No file uploaded", 400

        file = request.files["file"]

        if file.filename == "":
            return "Empty filename", 400

        filename = secure_filename(file.filename)

        try:
            # Upload directly to S3
            s3.upload_fileobj(
                file,
                S3_BUCKET,
                S3_FOLDER + filename
            )

            logger.info(
                f"File uploaded → {filename} from IP {request.remote_addr}"
            )

            return f"File uploaded successfully: {filename}"

        except Exception as e:

            logger.error(f"S3 upload failed → {str(e)}")

            return "Upload failed", 500

    return render_template_string(upload_page)


@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))

# =========================
# MAIN
# =========================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
    )