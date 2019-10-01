#!/usr/bin/python3
from flask import Flask, request, send_file, make_response
from flask_restful import Api
import helpers
import s3_helpers
import report_helpers
import git_helpers
from flask_cors import CORS

app = Flask(__name__)
api = Api(app)
CORS(app)

DCCSCR_WHITELIST_PROJECT_ID = 143


@app.route('/get', methods=['GET', 'POST'])
def get_all_the_things():
    image_name = request.args.get('name')
    image_ver = request.args.get('ver')
    proj = git_helpers.init(DCCSCR_WHITELIST_PROJECT_ID)
    return helpers.get_all_the_things_json(proj, image_name, image_ver)


@app.route('/get_all_whitelists')
def get_all_whitelists():
    return str(git_helpers.get_all_filename_and_refs_json(git_helpers.init(DCCSCR_WHITELIST_PROJECT_ID)))


@app.route('/last_runs', methods=['GET', 'POST'])
def get_last_run():
    map_url = request.args.get('url')
    return s3_helpers.get_last_n_runs(map_url, 5)


@app.route('/compare', methods=['GET', 'POST'])
def compare():
    url = request.args.get('url')
    return report_helpers.do_all_the_things(url)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port='8000')
