import os
import secrets
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from wtforms import SubmitField
from os.path import join, dirname, realpath

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = join(dirname(realpath(__file__)), 'static/uploads/')
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = ''
csrf = CSRFProtect(app)

class PostForm(FlaskForm):
    submit = SubmitField('Submit')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/' , methods=['GET', 'POST'])
def upload():
    form = PostForm()
    if form.validate_on_submit():
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secrets.token_hex(3) + secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file', filename=filename))
        else:
            flash('Bad forms' ,'danger')
    return render_template('upload.html',title="Home", form=form)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)
