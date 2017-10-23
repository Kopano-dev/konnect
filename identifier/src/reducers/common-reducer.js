import {
  RECEIVE_ERROR,
  RESET_HELLO,
  RECEIVE_HELLO
} from '../actions/action-types';

function commonReducer(state = {
  hello: null,
  error: null
}, action) {
  switch (action.type) {
    case RECEIVE_ERROR:
      return Object.assign({}, state, {
        error: action.error
      });

    case RESET_HELLO:
      return Object.assign({}, state, {
        hello: null
      });

    case RECEIVE_HELLO:
      return Object.assign({}, state, {
        hello: {
          state: action.state,
          username: action.username
        }
      });
    default:
      return state;
  }
}

export default commonReducer;
