import React from 'react';
import { connect } from 'react-redux';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import renderIf from 'render-if';

import Loading from './Loading';
import KopanoLogo from '../images/kopano-logo.svg';
import { executeHello, executeLogoff } from '../actions/common-actions';

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
  buttonGroup: {
    textAlign: 'right'
  },
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
    return (
      <Grid container justify="center" alignItems="center" spacing={0} className={classes.root}>
        <Grid item xs={10} sm={5} md={4} className={classes.limiter}>
          <Paper className={classes.paper} elevation={4}>
            <img src={KopanoLogo} className={classes.logo} alt="Kopano"/>
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

                <div className={classes.buttonGroup}>
                  <div className={classes.wrapper}>
                    <Button
                      color="secondary"
                      className={classes.button}
                      onClick={(event) => this.logoff(event)}
                    >Sign out</Button>
                  </div>
                </div>
              </div>
            ))}
            {renderIf(hello === null)(() => (
              <Loading/>
            ))}
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
