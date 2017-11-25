import React, { Component } from 'react';
import { connect } from 'react-redux';
import injectTapEventPlugin from 'react-tap-event-plugin';
import { BrowserRouter, Switch, Route } from 'react-router-dom';
import PropTypes from 'prop-types';

import '../styles/App.css';
import Loginscreen from '../components/Loginscreen';
import Welcomescreen from '../components/Welcomescreen';
import PrivateRoute from '../components/PrivateRoute';

// Needed for onTouchTap
// http://stackoverflow.com/a/34015469/988941
injectTapEventPlugin();

class App extends Component {
  render() {
    const { hello } = this.props;

    return (
      <BrowserRouter className="App" basename="/signin/v1">
        <Switch>
          <PrivateRoute path="/welcome" exact component={Welcomescreen} hello={hello}></PrivateRoute>
          <Route path="/" component={Loginscreen}></Route>
        </Switch>
      </BrowserRouter>
    );
  }
}

App.propTypes = {
  hello: PropTypes.object
};

const mapStateToProps = (state) => {
  const { hello } = state.common;

  return {
    hello
  };
};

export default connect(mapStateToProps)(App);
