===================
mod_fastcgi_handler
===================

:Author: `Benedikt Böhm <bb@xnull.de>`_
:Version: 0.1
:Web: http://bb.xnull.de/projects/mod_fastcgi_handler/
:Source: http://git.xnull.de/cgit/mod_fastcgi_handler/ (also on `github <http://github.com/hollow/mod_fastcgi_handler>`_)
:Download: http://bb.xnull.de/projects/mod_fastcgi_handler/dist/

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

TBD
