import { combineReducers } from 'redux';

import commonReducer from './common-reducer';
import loginReducer from './login-reducer';

const rootReducer = combineReducers({
  common: commonReducer,
  login: loginReducer
});

export default rootReducer;
