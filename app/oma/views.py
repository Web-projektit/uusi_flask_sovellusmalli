from flask import render_template, redirect, url_for, abort, flash, request, current_app, jsonify
from flask_login import login_required, current_user
from . import oma


@oma.route('/')
@oma.route('/<name>')
@login_required
def loma(name=None):
    return render_template('oma/oma.html',name=name)