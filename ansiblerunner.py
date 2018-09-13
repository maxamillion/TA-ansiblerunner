# Minimal set of standard modules to import
import csv      # Result set is in CSV format
import gzip     # Result set is gzipped
import json     # Payload comes in JSON format
import logging  # For specifying log levels
import sys      # For appending the library path
import time

# Standard modules specific to this action
import ansible_runner

# Importing the cim_actions.py library
# A.  Import make_splunkhome_path
# B.  Append your library path to sys.path
# C.  Import ModularAction from cim_actions
# D.  Import ModularActionTimer from cim_actions
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(
    make_splunkhome_path(["etc", "apps", "TA-haveibeenpwned", "lib"])
)
from cim_actions import ModularAction, ModularActionTimer

# Retrieve a logging instance from ModularAction
# It is required that this endswith _modalert
logger = ModularAction.setup_logger('haveibeenpwned_modalert')


# Subclass ModularAction for purposes of implementing
# a script specific dowork() method
class AnsibleRunnerModularAction(ModularAction):

    # This method will initialize AnsibleRunnerModularAction
    def __init__(self, settings, logger, action_name=None):
        # Call ModularAction.__init__
        super(AnsibleRunnerModularAction, self).__init__(
            settings, logger, action_name
        )
        # Initialize params
        self.hostpattern = self.configuration.get('hostpattern', 'localhost')
        self.playbook = self.configuration.get('playbook', None)
        self.verbose = self.configuration.get('verbose', False)

    # This method will handle validation
    def validate(self, result):
        # outer validation
        if len(self.rids) <= 1:
            # Validate param.playbook
            if not self.configuration.get('playbook'):
                raise Exception('Invalid playbook requested')

    # This method will do the actual work itself
    def dowork(self, result):
        arunner = ansible_runner.run(
            host_pattern=self.hostpattern,
            playbook=self.playbook,
            verbosity=1 if self.verbose else 0
        )
        if arunner.stats['failures']:
            self.message(arunner.stdout.read(), status='failed')
        else:
            self.message(arunner.stdout.read(), status='success')


if __name__ == "__main__":
    # This is standard chrome for validating that
    # the script is being executed by splunkd accordingly
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        print >> sys.stderr, "FATAL Unsupported execution mode (expected --execute flag)"
        sys.exit(1)

    # The entire execution is wrapped in an outer try/except
    try:
        # Retrieve an instanced of AnsibleRunnerModularAction and name it
        # modaction pass the payload (sys.stdin) and logging instance
        modaction = AnsibleRunnerModularAction(sys.stdin.read(), logger, 'haveibeenpwned')
        logger.debug(modaction.settings)

        # Add a duration message for the "main" component using
        # modaction.start_timer as the start time
        with ModularActionTimer(modaction, 'main', modaction.start_timer):
            # Process the result set by opening results_file with gzip
            with gzip.open(modaction.results_file, 'rb') as fh:
                # Iterate the result set using a dictionary reader
                # We also use enumerate which provides "num" which
                # can be used as the result ID (rid)
                for num, result in enumerate(csv.DictReader(fh)):
                    # results limiting
                    if num >= modaction.limit:
                        break
                    # Set rid to row # (0->n) if unset
                    result.setdefault('rid', str(num))
                    # Update the ModularAction instance
                    # with the current result.  This sets
                    # orig_sid/rid/orig_rid accordingly.
                    modaction.update(result)
                    # Generate an invocation message for each result.
                    # Tells splunkd that we are about to perform the action
                    # on said result.
                    modaction.invoke()
                    # Validate the invocation
                    modaction.validate(result)
                    # This is where we do the actual work.  In this case
                    # we are calling out to an external API and creating
                    # events based on the information returned
                    modaction.dowork(result)
                    # rate limiting
                    time.sleep(1.6)

            # Once we're done iterating the result set and making
            # the appropriate API calls we will write out the events
            modaction.writeevents(index='haveibeenpwned', source='haveibeenpwned')

    # This is standard chrome for outer exception handling
    except Exception as e:
        # adding additional logging since adhoc search invocations do not write
        # to stderr
        try:
            modaction.message(e, status='failure', level=logging.CRITICAL)
        except:
            logger.critical(e)
        print >> sys.stderr, "ERROR: %s" % e
        sys.exit(3)
