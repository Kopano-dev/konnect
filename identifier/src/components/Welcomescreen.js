import React from 'react';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';

import KopanoLogo from '../images/kopano-logo.svg';
import { executeLogoff } from '../actions/common-actions';

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
  }),
  subHeader: {
    marginBottom: theme.spacing.unit * 5
  }
});

class Welcomescreen extends React.PureComponent {
  render() {
    const { classes, hello } = this.props;
    return (
      <Grid container justify="center" alignItems="center" spacing={0} className={classes.root}>
        <Grid item xs={10} sm={5} md={4} className={classes.limiter}>
          <Paper className={classes.paper} elevation={4}>
            <img src={KopanoLogo} className={classes.logo} alt="Kopano"/>
            <div>
              <Typography variant="headline" component="h3">
                Welcome {hello.displayName}
              </Typography>
              <Typography variant="subheading" className={classes.subHeader}>
                {hello.username}
              </Typography>

              <Typography gutterBottom>
                You are signed in - awesome!
              </Typography>

              <Button
                variant="raised"
                className={classes.button}
                onClick={(event) => this.logoff(event)}
              >Sign out</Button>
            </div>
          </Paper>
        </Grid>
      </Grid>
    );
  }

  logoff(event) {
    event.preventDefault();

    this.props.dispatch(executeLogoff()).then((response) => {
      const { history } = this.props;

      if (response.success) {
        history.push('/identifier');
      }
    });
  }
}

Welcomescreen.propTypes = {
  classes: PropTypes.object.isRequired,

  hello: PropTypes.object,

  dispatch: PropTypes.func.isRequired,
  history: PropTypes.object.isRequired
};

const mapStateToProps = (state) => {
  const { hello } = state.common;

  return {
    hello
  };
};

export default connect(mapStateToProps)(withStyles(styles)(Welcomescreen));
