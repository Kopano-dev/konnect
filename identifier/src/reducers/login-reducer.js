import {
  RECEIVE_VALIDATE_LOGON,
  REQUEST_LOGON,
  RECEIVE_LOGON,
  UPDATE_INPUT
} from '../actions/action-types';

function loginReducer(state = {
  loading: false,
  username: '',
  password: '',
  errors: {}
}, action) {
  switch (action.type) {
    case RECEIVE_VALIDATE_LOGON:
      return Object.assign({}, state, {
        errors: action.errors,
        loading: false
      });

    case REQUEST_LOGON:
      return Object.assign({}, state, {
        loading: true
      });

    case RECEIVE_LOGON:
      if (!action.state) {
        return Object.assign({}, state, {
          errors: action.errors,
          loading: false
        });
      }
      return state;

    case UPDATE_INPUT:
      delete state.errors[action.name];
      return Object.assign({}, state, {
        [action.name]: action.value
      });

    default:
      return state;
  }
}

export default loginReducer;
