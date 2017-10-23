import React, { Component } from 'react';
import injectTapEventPlugin from 'react-tap-event-plugin';
import { BrowserRouter, Switch, Route } from 'react-router-dom';

import '../styles/App.css';
import Loginscreen from '../components/Loginscreen';

// Needed for onTouchTap
// http://stackoverflow.com/a/34015469/988941
injectTapEventPlugin();

class App extends Component {
  render() {
    return (
      <BrowserRouter className="App" basename="/signin/v1">
        <Switch>
          <Route path="/" component={Loginscreen}></Route>
        </Switch>
      </BrowserRouter>
    );
  }
}

export default App;
