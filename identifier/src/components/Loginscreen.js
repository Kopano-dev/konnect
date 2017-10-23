import React, { Component } from 'react';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';
import { withStyles } from 'material-ui/styles';
import Paper from 'material-ui/Paper';
import Grid from 'material-ui/Grid';
import { Route, Switch, Redirect } from 'react-router-dom';
import renderIf from 'render-if';

import Login from './Login';
import Chooseaccount from './Chooseaccount';
import Consent from './Consent';
import Loading from './Loading';
import KopanoLogo from '../images/kopano-logo.svg';
import Background from '../images/loginscreen-bg.jpg';
import { executeHello } from '../actions/common-actions';

const styles = theme => ({
  root: {
    height: '100vh',
    backgroundImage: 'url(' + Background + ')',
    backgroundPosition: 'bottom',
    backgroundSize: 'cover',
    backgroundRepeat: 'no-repeat'
  },
  logo: {
    height: 18,
    marginBottom: theme.spacing.unit * 2
  },
  paper: theme.mixins.gutters({
    backgroundColor: 'rgba(255,255,255,0.85)',
    paddingTop: 48,
    paddingBottom: 36,
    minHeight: 400,
    maxWidth: 400,
    position: 'relative'
  })
});

class Loginscreen extends Component {
  componentDidMount() {
    this.props.dispatch(executeHello());
  }

  render() {
    const { classes, hello } = this.props;
    return (
      <Grid container justify="center" alignItems="center" spacing={0} className={classes.root}>
        <Grid item xs={10} sm={5} md={4}>
          <Paper className={classes.paper} elevation={4}>
            <img src={KopanoLogo} className={classes.logo} alt="Kopano"/>
            {renderIf(hello !== null)(() => (
              <Switch>
                <Route path="/identifier" exact component={Login}></Route>
                <Route path="/chooseaccount" exact component={Chooseaccount}></Route>
                <Route path="/consent" exact component={Consent}></Route>
                <Route path="/welcome" exact></Route>
                <Redirect to="/identifier"/>
              </Switch>
            ))}
            {renderIf(hello === null)(() => (
              <Loading/>
            ))}
          </Paper>
        </Grid>
      </Grid>
    );
  }
}

Loginscreen.propTypes = {
  classes: PropTypes.object.isRequired,

  hello: PropTypes.object,

  dispatch: PropTypes.func.isRequired
};

const mapStateToProps = (state) => {
  const { hello } = state.common;

  return {
    hello
  };
};

export default connect(mapStateToProps)(withStyles(styles)(Loginscreen));
