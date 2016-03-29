from flask import Blueprint

auth = BluePrint('auth', __name__)

from . import views
