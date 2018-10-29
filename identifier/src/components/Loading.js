import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';

import { FormattedMessage } from 'react-intl';

import { withStyles } from '@material-ui/core/styles';
import LinearProgress from '@material-ui/core/LinearProgress';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import renderIf from 'render-if';

import { retryHello } from '../actions/common-actions';

const styles = theme => ({
  root: {
    flexGrow: 1,
    position: 'absolute',
    top: 0,
    bottom: 0,
    left: 0,
    right: 0
  },
  progress: {
    height: '4px',
    width: '100px'
  },
  button: {
    marginTop: theme.spacing.unit * 5
  }
});

class Loading extends Component {
  render() {
    const { classes, error } = this.props;

    return (
      <Grid container direction="column" alignItems="center" justify="center" spacing={0} className={classes.root}>
        <Grid item align="center">
          {renderIf(error === null)(() => (
            <LinearProgress className={classes.progress} />
          ))}
          {renderIf(error !== null)(() => (
            <div>
              <Typography variant="headline" gutterBottom align="center">
                <FormattedMessage id="konnect.loading.error.headline" defaultMessage="Failed to connect to Kopano">
                </FormattedMessage>
              </Typography>
              <Typography variant="body1" gutterBottom align="center" color="error">
                {error.message}
              </Typography>
              <Button
                autoFocus
                variant="raised"
                className={classes.button}
                onClick={(event) => this.retry(event)}
              >
                <FormattedMessage id="konnect.login.retryButton.label" defaultMessage="Retry"></FormattedMessage>
              </Button>
            </div>
          ))}
        </Grid>
      </Grid>
    );
  }

  retry(event) {
    event.preventDefault();

    this.props.dispatch(retryHello());
  }
}

Loading.propTypes = {
  classes: PropTypes.object.isRequired,

  error: PropTypes.object,

  dispatch: PropTypes.func.isRequired
};

const mapStateToProps = (state) => {
  const { error } = state.common;

  return {
    error
  };
};

export default connect(mapStateToProps)(withStyles(styles)(Loading));
