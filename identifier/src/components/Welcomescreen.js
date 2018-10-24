import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';

import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import DialogActions from '@material-ui/core/DialogActions';

import ResponsiveScreen from './ResponsiveScreen';
import { executeLogoff } from '../actions/common-actions';

const styles = theme => ({
  subHeader: {
    marginBottom: theme.spacing.unit * 5
  }
});

class Welcomescreen extends React.PureComponent {
  render() {
    const { classes, hello } = this.props;

    const loading = hello === null;
    return (
      <ResponsiveScreen loading={loading}>
        <Typography variant="headline" component="h3">
          Welcome {hello.displayName}
        </Typography>
        <Typography variant="subheading" className={classes.subHeader}>
          {hello.username}
        </Typography>

        <Typography gutterBottom>
          You are signed in - awesome!
        </Typography>

        <DialogActions>
          <Button
            color="secondary"
            className={classes.button}
            onClick={(event) => this.logoff(event)}
          >Sign out</Button>
        </DialogActions>
      </ResponsiveScreen>
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
