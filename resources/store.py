from flask_restful import Resource
from models.Store import StoreModel
from flask_jwt_extended import jwt_required, fresh_jwt_required


class Store(Resource):
    @jwt_required
    def get(self, name):
        store = StoreModel.find_by_name(name)
        if store:
            return store.json()
        return {'message': 'Store not found'}, 404

    @fresh_jwt_required
    def post(self, name):
        if StoreModel.find_by_name(name):
            return {'message': "A store with name '{}' already exists".format(name)}, 400
        store = StoreModel(name)
        try:
            store.save_to_db()
        except:
            return {'message': 'An error occurred while creating store'}, 500
        return store.json(), 201

    @jwt_required
    def delete(self, name):
        store = StoreModel.find_by_name(name)
        if store:
            store.delete()
        return {'message': 'Store deleted'}


class StoreList(Resource):
    @jwt_required
    def get(self):
        return {'stores': [store.json() for store in StoreModel.query.all()]}
