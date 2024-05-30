from flask.sessions import SecureCookieSessionInterface

class CustomSessionInterface(SecureCookieSessionInterface):
    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')

        if not session:
            if session.modified:
                response.delete_cookie(cookie_name, domain=domain)
            return

        cookie_samesite = app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')
        cookie_secure = app.config.get('SESSION_COOKIE_SECURE', False)
        cookie_httponly = app.config.get('SESSION_COOKIE_HTTPONLY', True)

        response.set_cookie(cookie_name,
                            self.get_signing_serializer(app).dumps(dict(session)),
                            max_age=session.permanent and app.permanent_session_lifetime or None,
                            expires=self.get_expiration_time(app, session),
                            domain=domain,
                            path=self.get_cookie_path(app),
                            secure=cookie_secure,
                            httponly=cookie_httponly,
                            samesite=cookie_samesite)
