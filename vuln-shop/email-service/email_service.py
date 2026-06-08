# email_service.py - tiny Flask app that renders email templates with Jinja2.
# DELIBERATELY VULNERABLE to SSTI via render_template_string.
from flask import Flask, request, jsonify, render_template_string
import os, sys

app = Flask(__name__)

@app.route('/health')
def health():
    return jsonify(ok=True, service='vuln-shop email service')

@app.route('/render', methods=['POST'])
def render():
    data = request.get_json(silent=True) or {}
    template = data.get('template', '')
    context = data.get('context', {})
    if not isinstance(context, dict):
        context = {}
    # VULN: passes user-supplied template through Jinja's full evaluator.
    try:
        rendered = render_template_string(template, **context)
        return rendered, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as exc:
        # VULN: leaks internal exception details
        return ('render error: ' + repr(exc)), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', '5002'))
    host = os.environ.get('HOST', '0.0.0.0')
    print('vuln-shop email-service listening on http://{}:{}/render'.format(host, port), file=sys.stderr)
    app.run(host=host, port=port, debug=False)
