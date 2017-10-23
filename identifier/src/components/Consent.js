import React, { Component } from 'react';
import { connect } from 'react-redux';
import { withStyles } from 'material-ui/styles';
import PropTypes from 'prop-types';
import Button from 'material-ui/Button';
import { CircularProgress } from 'material-ui/Progress';
import green from 'material-ui/colors/green';
import Typography from 'material-ui/Typography';

const styles = theme => ({
  button: {
    margin: theme.spacing.unit
  },
  buttonProgress: {
    color: green[500],
    position: 'absolute',
    top: '50%',
    left: '50%',
    marginTop: -12,
    marginLeft: -12
  },
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
  },
  message: {
    marginTop: theme.spacing.unit * 2
  }
});

class Login extends Component {
  render() {
    const { classes, loading } = this.props;
    return (
      <div>
        <Typography type="headline" component="h3">
          Request for permission
        </Typography>
        <Typography type="subheading" className={classes.subHeader}>
          please check and allow or cancel this request
        </Typography>

        <form action="" onSubmit={(event) => this.logon(event)}>

          <div className={classes.buttonGroup}>
            <Button color="primary" className={classes.button}>
              Cancel
            </Button>
            <div className={classes.wrapper}>
              <Button
                type="submit"
                raised
                color="primary"
                className={classes.button}
                disabled={loading}
                onClick={(event) => this.allow(event)}
              >Allow</Button>
              {loading && <CircularProgress size={24} className={classes.buttonProgress} />}
            </div>
          </div>
        </form>
      </div>
    );
  }

  allow(event) {
    event.preventDefault();

  }
}

Login.propTypes = {
  classes: PropTypes.object.isRequired,

  loading: PropTypes.bool.isRequired,

  dispatch: PropTypes.func.isRequired
};

const mapStateToProps = () => {
  return {
    loading: false
  };
};

export default connect(mapStateToProps)(withStyles(styles)(Login));
