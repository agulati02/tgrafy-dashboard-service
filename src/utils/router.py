from typing import Callable, Any, TypeAlias, Dict
from aws_lambda_powertools.utilities.typing import LambdaContext


DICT_STR_ANY_TYPE: TypeAlias = Dict[str, Any]
HANDLER_FUNCTION_TYPE: TypeAlias = Callable[[DICT_STR_ANY_TYPE, LambdaContext], DICT_STR_ANY_TYPE]

class Router:
    def __init__(self):
        self.routes: dict[str, HANDLER_FUNCTION_TYPE] = {}
    
    def route(self, action: str, path: str) -> Callable[[HANDLER_FUNCTION_TYPE], HANDLER_FUNCTION_TYPE]:
        def decorator(handler: HANDLER_FUNCTION_TYPE) -> HANDLER_FUNCTION_TYPE:
            self.routes[f"{action}:{path}"] = handler
            return handler
        return decorator
    
    def handle(self, event: DICT_STR_ANY_TYPE, context: LambdaContext) -> DICT_STR_ANY_TYPE:
        route_key = f"{event['httpMethod']}:{event['path']}"
        handler = self.routes.get(route_key)
        
        if handler:
            return handler(event, context)
        else:
            return {'statusCode': 404, 'body': 'Not Found'}