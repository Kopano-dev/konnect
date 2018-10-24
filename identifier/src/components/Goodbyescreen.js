import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';

import renderIf from 'render-if';

import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import DialogActions from '@material-ui/core/DialogActions';

import ResponsiveScreen from './ResponsiveScreen';
import { executeHello, executeLogoff } from '../actions/common-actions';

const styles = theme => ({
  subHeader: {
    marginBottom: theme.spacing.unit * 5
  },
  wrapper: {
    marginTop: theme.spacing.unit * 5,
    position: 'relative',
    display: 'inline-block'
  }
});

class Goodbyescreen extends React.PureComponent {
  componentDidMount() {
    this.props.dispatch(executeHello());
  }

  render() {
    const { classes, hello } = this.props;

    const loading = hello === null;
    return (
      <ResponsiveScreen loading={loading}>
        {renderIf(hello !== null && !hello.state)(() => (
          <div>
            <Typography variant="headline" component="h3">
              Goodbye
            </Typography>
            <Typography variant="subheading" className={classes.subHeader}>
              you have been signed out from your Kopano account
            </Typography>

            <Typography gutterBottom>
              You can close this window now.
            </Typography>
          </div>
        ))}
        {renderIf(hello !== null && hello.state === true)(() => (
          <div>
            <Typography variant="headline" component="h3">
              Hello {hello.displayName}
            </Typography>
            <Typography variant="subheading" className={classes.subHeader}>
              please confirm sign out
            </Typography>

            <Typography gutterBottom>
              Press the button below, to sign out from your Kopano account now.
            </Typography>

            <DialogActions>
              <div className={classes.wrapper}>
                <Button
                  color="secondary"
                  className={classes.button}
                  onClick={(event) => this.logoff(event)}
                >Sign out</Button>
              </div>
            </DialogActions>
          </div>
        ))}
      </ResponsiveScreen>
    );
  }

  logoff(event) {
    event.preventDefault();

    this.props.dispatch(executeLogoff()).then((response) => {
      const { history } = this.props;

      if (response.success) {
        this.props.dispatch(executeHello());
        history.push('/goodbye');
      }
    });
  }
}

Goodbyescreen.propTypes = {
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

export default connect(mapStateToProps)(withStyles(styles)(Goodbyescreen));
