import mysql.connector

import click
from flask import current_app, g
from flask.cli import with_appcontext

from .schemas import instructions

def get_db():
    if 'db' not in g:
        g.db = mysql.connector.connect(
            host=current_app.config['DATABASE_HOST'],
            user=current_app.config['DATABASE_USER'],
            password=current_app.config['DATABASE_PASSWORD'],
            database=current_app.config['DATABASE']
        )
        g.c = g.db.cursor(dictionary=True)
    return g.db, g.c

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


@click.command('init-db')
@with_appcontext
def init_db():
    db, c = get_db()

    for instruction in instructions:
        c.execute(instruction)
    db.commit()


def inid_db_command():
    init_db()
    click.echo('DB initialized!')


def init_app(app):
    app.teardown_appcontext(close_db)