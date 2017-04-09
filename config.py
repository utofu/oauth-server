import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = "sqlite:////tmp/poe.sql"
    @staticmethod
    def init_app(app):
        pass

class TestingConfig(Config):
    TESTING = True

class DevelopConfig(Config):
    DEBUG = True

class MasterConfig(Config):
    DEBUG = True


config = {
        "default": MasterConfig,
        "develop": DevelopConfig,
        "testing": TestingConfig,
        "master": MasterConfig,
        "ci": TestingConfig
        }
