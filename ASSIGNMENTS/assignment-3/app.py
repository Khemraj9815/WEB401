"""
Secure File Upload
A small Flask web application that lets a user upload a file and applies
several security measures to prevent malicious file uploads.
"""

import os
import secrets
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Store uploads in a dedicated folder that is NOT served as executable code.
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# SAFEGUARD 1: size limit. Flask rejects anything larger automatically.
MAX_FILE_SIZE = 2 * 1024 * 1024               # 2 MB
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

# SAFEGUARD 2: extension allowlist (we only allow safe image types).
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# SAFEGUARD 3: the real file formats we accept, confirmed by actually
# trying to open the file as an image (see content_is_real_image).
ALLOWED_IMAGE_CONTENT = {"PNG", "JPEG", "GIF"}


def extension_is_allowed(filename: str) -> bool:
    """Check the extension against the allowlist."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def content_is_real_image(stream) -> bool:
    """
    SAFEGUARD 3 in action: actually open the uploaded bytes as an image.
    A file named 'cat.png' that really contains PHP code will fail here,
    because Pillow cannot parse it as a valid image. verify() checks the
    internal structure, not just the first few bytes.
    """
    from PIL import Image
    try:
        img = Image.open(stream)
        img.verify()                          # raises if not a real image
        ok = img.format in ALLOWED_IMAGE_CONTENT
    except Exception:
        ok = False
    finally:
        stream.seek(0)                        # rewind so we can still save it
    return ok


@app.route("/")
def index():
    return render_template("index.html", allowed=sorted(ALLOWED_EXTENSIONS))


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify(ok=False, msg="No file part in the request."), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify(ok=False, msg="No file selected."), 400

    # SAFEGUARD 4: sanitize the filename.
    # secure_filename() strips directory paths like ../../ and dangerous
    # characters, preventing path traversal (e.g. "../../etc/passwd").
    safe_name = secure_filename(file.filename)
    if safe_name == "":
        return jsonify(ok=False, msg="Invalid filename."), 400

    # SAFEGUARD 1: extension allowlist.
    if not extension_is_allowed(safe_name):
        return jsonify(ok=False, msg="File type not allowed. Allowed: png, jpg, jpeg, gif."), 400

    # SAFEGUARD 3: verify the actual content is an image.
    if not content_is_real_image(file.stream):
        return jsonify(ok=False, msg="File content is not a valid image (possible disguised file)."), 400

    # SAFEGUARD 5: rename the file to a random name and force a safe
    # extension. This stops overwriting other files and removes any
    # tricky double extensions such as "shell.php.png".
    ext = safe_name.rsplit(".", 1)[1].lower()
    new_name = secrets.token_hex(16) + "." + ext
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], new_name)

    file.save(save_path)

    return jsonify(ok=True, msg=f"Upload accepted and stored as {new_name}", stored=new_name)


# SAFEGUARD 1 (friendly message when the size limit is exceeded)
@app.errorhandler(413)
def too_large(e):
    return jsonify(ok=False, msg="File too large. Maximum size is 2 MB."), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)