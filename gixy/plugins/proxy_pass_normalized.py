import re
import gixy
from gixy.plugins.plugin import Plugin

class proxy_pass_normalized(Plugin):
    r"""
    This plugin detects if there is any path component (slash or more)
    after the host in a proxy_pass directive.
    Example flagged directives:
        proxy_pass http://backend/;
        proxy_pass http://backend/foo/bar;
    """

    summary = 'Detect path after host in proxy_pass (potential URL decoding issue)'
    severity = gixy.severity.LOW
    description = ("A slash immediately after the host in proxy_pass leads to the path being decoded and normalized before proxying downstream, leading to unexpected behavior related to encoded slashes.")
    help_url = 'https://joshua.hu/proxy-pass-nginx-decoding-normalizing-url-path-dangerous#nginx-proxy_pass'
    directives = ['proxy_pass']

    def __init__(self, config):
        super(proxy_pass_normalized, self).__init__(config)
        self.parse_uri_re = re.compile(r'(?P<scheme>[^?#/)]+://)?(?P<host>[^?#/)]+)(?P<path>/.*)?')

    def audit(self, directive):
        proxy_pass_arg = directive.args[0]
        if not proxy_pass_arg:
            return

        parsed = self.parse_uri_re.match(proxy_pass_arg)

        if not parsed:
            return

        if not parsed.group('path'):
            return

        self.add_issue(
            severity=self.severity,
            directive=[directive, directive.parent],
            reason=(
                "Found a slash (and possibly more) after the hostname in proxy_pass. "
                "This can lead to path decoding issues."
            )
        )
