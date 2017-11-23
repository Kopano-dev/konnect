import {
  RECEIVE_ERROR,
  RESET_HELLO,
  RECEIVE_HELLO
} from '../actions/action-types';
import queryString from 'query-string';

const query = queryString.parse(document.location.search);
const flow = query.flow || '';
delete query.flow;

const defaultState = {
  hello: null,
  error: null,
  flow: flow,
  query: query
};

function commonReducer(state = defaultState, action) {
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
          username: action.username,
          details: action.hello
        }
      });
    default:
      return state;
  }
}

export default commonReducer;
