import React from 'react';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import { Route, Switch } from 'react-router-dom';
import renderIf from 'render-if';

import Login from './Login';
import Chooseaccount from './Chooseaccount';
import Consent from './Consent';
import Loading from './Loading';
import RedirectWithQuery from './RedirectWithQuery';
import KopanoLogo from '../images/kopano-logo.svg';
import { executeHello } from '../actions/common-actions';

const styles = theme => ({
  root: {
    display: 'flex',
    flex: 1
  },
  logo: {
    height: 18,
    marginBottom: theme.spacing.unit * 2
  },
  limiter: {
    maxWidth: 450
  },
  paper: theme.mixins.gutters({
    backgroundColor: 'white',
    paddingTop: 48,
    paddingBottom: 36,
    minHeight: 400,
    position: 'relative'
  })
});

class Loginscreen extends React.PureComponent {
  componentDidMount() {
    this.props.dispatch(executeHello());
  }

  render() {
    const { classes, hello } = this.props;
    return (
      <Grid container justify="center" alignItems="center" spacing={0} className={classes.root}>
        <Grid item xs={10} sm={5} md={4} className={classes.limiter}>
          <Paper className={classes.paper} elevation={4}>
            <img src={KopanoLogo} className={classes.logo} alt="Kopano"/>
            {renderIf(hello !== null)(() => (
              <Switch>
                <Route path="/identifier" exact component={Login}></Route>
                <Route path="/chooseaccount" exact component={Chooseaccount}></Route>
                <Route path="/consent" exact component={Consent}></Route>
                <RedirectWithQuery target="/identifier"/>
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
