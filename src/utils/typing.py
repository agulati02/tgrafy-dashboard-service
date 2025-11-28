from typing import Callable, Any, TypeAlias, Dict
from aws_lambda_powertools.utilities.typing import LambdaContext


DICT_STR_ANY_TYPE: TypeAlias = Dict[str, Any]
HANDLER_FUNCTION_TYPE: TypeAlias = Callable[[DICT_STR_ANY_TYPE, LambdaContext], DICT_STR_ANY_TYPE]