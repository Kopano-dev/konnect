import React from 'react';
import PropTypes from 'prop-types';

import { Route, Switch } from 'react-router-dom';
import AsyncComponent from 'kpop/es/AsyncComponent';

import PrivateRoute from './components/PrivateRoute';

const AsyncLogin = AsyncComponent(() =>
  import(/* webpackChunkName: "containers-login" */ './components/Loginscreen'));
const AsyncWelcome = AsyncComponent(() =>
  import(/* webpackChunkName: "containers-welcome" */ './components/Welcomescreen'));
const AsyncGoodbye = AsyncComponent(() =>
  import(/* webpackChunkName: "containers-goodbye" */ './components/Goodbyescreen'));

const Routes = ({ hello }) => (
  <Switch>
    <PrivateRoute
      path="/welcome"
      exact
      component={AsyncWelcome}
      hello={hello}
    />
    <Route
      path="/goodbye"
      exact
      component={AsyncGoodbye}
    />
    <Route
      path="/"
      component={AsyncLogin}
    />
  </Switch>
);

Routes.propTypes = {
  hello: PropTypes.object
};

export default Routes;
