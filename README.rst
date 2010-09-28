===================
mod_fastcgi_handler
===================

:Author: `Benedikt Böhm <bb@xnull.de>`_
:Version: 0.3
:Web: http://github.com/hollow/mod_fastcgi_handler
:Git: ``git clone https://github.com/hollow/mod_fastcgi_handler.git``
:Download: http://github.com/hollow/mod_fastcgi_handler/downloads

mod_fastcgi_handler is a very simple FastCGI implementation derived from
mod_fastcgi and mod_proxy_fcgi. mod_fastcgi_handler does not implement a
process manager, nor does it support Authenticator and Authorizer roles.
mod_fastcgi_handler is a module for rapidly deploying FastCGI applications with
Apache.

Rationale
=========

mod_fastcgi and mod_fcgid both include a huge process manager code, which is
not needed with a typical FastCGI application. Such applications, including
Django and PHP-FPM, ship their own process manager and provide a socket to
communication with the web server. Thus a simple mechanism for talking to this
socket is required. While mod_fastcgi and mod_proxy_fcgi both provide such a
feature, the former has a quite complex configuration syntax while the latter
does not support unix domain sockets.

The solution is to provide simple handler for external FastCGI applications.

Installation
============

To compile and install this module, use ``apxs`` provided by the apache
webserver:
::

  apxs -i -a -o mod_fastcgi_handler.so -c *.c

Configuration
=============

mod_fastcgi_handler provides a handler that can be activated by using the
``AddHandler`` and ``SetHandler`` directives. To use mod_fastcgi_handler with
PHP-FPM add the following option to your httpd.conf:
::

  AddHandler fcgi:/var/run/php-fpm.socket .php

To use mod_fastcgi_handler with a Django FastCGI application running on port 3000:
::

  <Location />
    SetHandler fcgi:127.0.0.1:3000
  </Location>

Bugs
====

mod_fastcgi_handler is beta-quality software. It has not been widely tested,
and some production-critical features, like non-blocking sockets and timeouts
have not yet been implemented.
