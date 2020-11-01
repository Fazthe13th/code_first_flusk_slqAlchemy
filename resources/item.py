from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_claims
from models.Item import ItemModel


class Item(Resource):
    purser = reqparse.RequestParser()
    purser.add_argument(
        'price', required=True, type=float, help='Can not be blank'
    )
    purser.add_argument(
        'store_id', required=True, type=int, help='Store ID should not be empty'
    )

    @jwt_required
    def get(self, name):
        item = ItemModel.find_by_name(name)
        if item:
            return item.json()
        return {'message': 'Item not found'}, 404

    @jwt_required
    def post(self, name):
        if ItemModel.find_by_name(name):
            return {'message': 'An item with that name {} already exixts'.format(name)}, 400
        request_data = Item.purser.parse_args()
        item = ItemModel(name, **request_data)
        try:
            item.save_to_db()
        except:
            return {'message': 'An error happed in the item'}, 500  # internal server error
        return item.json(), 201

    @jwt_required
    def delete(self, name):
        claims = get_jwt_claims()
        if not claims['is_admin']:
            return {'message': 'Admin privilege required'}, 401
        item = ItemModel.find_by_name(name)
        if item:
            item.delete()
            return {'message': 'item deleted'}, 200

    @jwt_required
    def put(self, name):

        request_data = Item.purser.parse_args()

        item = ItemModel.find_by_name(name)
        if item is None:
            item = ItemModel(name, **request_data)
        else:
            item.price = request_data['price']
        item.save_to_db()
        return item.json(), 200


class ItemList(Resource):
    @jwt_required
    def get(self):
        return {'items': [item.json() for item in ItemModel.query.all()]}
