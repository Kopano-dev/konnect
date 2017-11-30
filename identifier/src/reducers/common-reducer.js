import {
  RECEIVE_ERROR,
  RESET_HELLO,
  RECEIVE_HELLO,
  SERVICE_WORKER_NEW_CONTENT
} from '../actions/action-types';
import queryString from 'query-string';

const query = queryString.parse(document.location.search);
const flow = query.flow || '';
delete query.flow;

const defaultState = {
  hello: null,
  error: null,
  flow: flow,
  query: query,
  updateAvailable: false
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
          displayName: action.displayName,
          details: action.hello
        }
      });

    case SERVICE_WORKER_NEW_CONTENT:
      return Object.assign({}, state, {
        updateAvailable: true
      });

    default:
      return state;
  }
}

export default commonReducer;
