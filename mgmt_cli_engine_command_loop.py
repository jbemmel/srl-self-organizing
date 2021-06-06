###########################################################################
# Description:
#
# Copyright (c) 2018 Nokia
###########################################################################
from .array_reader import ArrayReader
from .command_executor import CommandsExecutor
from .line_parser import LineParser
from .line_parser_auto_completer import LineParserAutoCompleter
from .line_parser_auto_suggester import LineParserAutoSuggester
from .multiline_string_reader import MultilineStringReader
from .space_auto_complete_decorator import SpaceAutoCompleteDecorator
from srlinux.asserts import assert_is_instance_of
from srlinux.mgmt.cli import CliState, ExecuteError, SessionTerminate, ParseError, Observer
from srlinux.mgmt.cli.global_state import get_global_state
from srlinux.mgmt.cli.idle_timer import get_idle_task
from srlinux.mgmt.cli.cli_mode import CliMode
from srlinux.mgmt.cli.configuration_session_type import ConfigurationSessionType
from srlinux.mgmt.server.server_error import ServerError
from srlinux.output import Output
import functools
import traceback

# JvB added
import re
import os
from srlinux.location import build_path
from srlinux.data import utilities

class CommandLoop(object):
    ''' Main executable class for any CLI engine.
        It will:
            - Read one line of input
            - Parse it into a list of 'Command's
            - Execute each of these 'Command's
            - Repeat until the input is empty

        Arguments:
           commands_reader: [type CommandsReader] Returns the input line-by-line
           line_parser: [type LineParser] Class responsible for parsing input-lines
           command_executor: [type CommandsExecutor] Class responsible for executing commands
           output: [type Output] Class where errors are printed
           stop_on_error: [type bool] If true execution stops after the first error
           observer: [type Observer] Optional observer that will be informed of each input line.
    '''

    def __init__(self,
                 commands_reader,
                 line_parser,
                 command_executor,
                 output,
                 state,
                 observer=None,
                 stop_on_error=False):
        assert_is_instance_of(line_parser, LineParser)
        assert_is_instance_of(command_executor, CommandsExecutor)
        assert_is_instance_of(output, Output)
        assert_is_instance_of(state, CliState)
        self._commands_reader = commands_reader
        self._input_reader = _add_decorators(commands_reader)
        self._line_parser = line_parser
        self._command_executor = command_executor
        self._state = state
        self._output = output
        self._stop_on_error = stop_on_error
        self._error_count = 0
        self._observer = observer or Observer()

    def loop(self):
        try:
            self._try_to_loop()
            if not self._state.is_switch_to_new_cli_engine_requested:
                self._observer.on_exit('quit was requested')
                # quitting via quit command, make sure the post lines still run
                # TODO(akocis): rework this to be more general and not rely on a specific function
                if hasattr(self._commands_reader, '_advance_to_next_reader'):
                    self._state._is_terminate_requested = False
                    try:
                        self._commands_reader._advance_to_next_reader()
                        self._try_to_loop()
                    finally:
                        self._state._is_terminate_requested = True
        except EOFError:
            # No more input lines
            self._observer.on_exit('Received EOF')
            return
        except Exception as e:
            # Catch unexpected exceptions, log them and reraise
            self._observer.on_exit(f'Uncaught exception {e}: {traceback.format_exc()}')
            raise

    def _try_to_loop(self):
        while not self._must_stop():
            self._process_line(self._next_input_line())
            get_idle_task().reset_idle_state()

    def _next_input_line(self):
        return self._input_reader.read_command(
            state=self._state,
            output=self._output,
            auto_completer=LineParserAutoCompleter(self._line_parser),
            auto_suggester=LineParserAutoSuggester(self._line_parser),
        )

    #  def _are_optional_objects_equal(self, left, right):
    #      if left is None:
    #          return right is None
    #      if right is None:
    #          return False
    #      return left == right

    def _check_for_configuration_session_termination(self):
        #  if not self._are_optional_objects_equal(self._state.server.configuration_session,
        #                                          self._state.configuration_session):
        if self._state.server.configuration_session != self._state.configuration_session:
            # discrepancy between 'enter candidate' local session type and server's session type
            # session must have been terminated from the server (e.g. tools system configuration session clear command)
            if self._state.server.configuration_session_type == ConfigurationSessionType.None_ and \
                    self._state.configuration_session_type != ConfigurationSessionType.None_:
                # if there is no configuration session on the server, we must drop to the running mode
                # double check if the configuration session is not created on the server
                if not self._state.server.query_session():
                    self._state.mode = CliMode.Running
                    self._state.server.update_session(configuration_session=self._state.configuration_session,
                                                      create=False)
                    self._output.print_warning_line('Your configuration session was terminated.')

    def _process_vars(self, line):

        def _lookup(match): # match looks like ${/path/x}
          _m = match[2:-1]  # Strip '${' and '}'
          if _m[0]!="/":
              self._output.print_warning_line( f'Lookup ENV var={match}' )
              return os.environ[ _m ]

          self._output.print_warning_line( f'Lookup variable path={match}' )
          _path_parts = _m.split('/')
          _leafkey = _path_parts[-1].split('#') # Allow '#' for use with keys
          _root = '/'.join( _path_parts[0:-2] ) + '/' + _leafkey[0]
          _leaf = utilities.sanitize_name( _leafkey[0] )
          _path = build_path( _root )
          # This returns a / node
          _data = self._state.server_data_store.get_data(_path,recursive=False,include_field_defaults=True)
          _result = getattr( _data.get_first_descendant(_root), _leaf)
          self._output.print_warning_line( f'path={match} -> {_result} type={type(_result)}' )
          # list address -> key ip-prefix, or container bgp -> leaf router-id
          if len(_leafkey) > 1:
              _key = utilities.sanitize_name( _leafkey[1] )
              return str( getattr( _result.get(), _key ) )
          else:
              return str( _result ) # leaf value

        return re.sub('\$\{(.*)\}', lambda m: _lookup(m.group()), line)

    def _process_line(self, line):
        get_global_state().operation_terminated = False
        try:
            if self._state.is_session_terminated:
                raise SessionTerminate('')

            self._check_for_configuration_session_termination()
            line = self._process_vars(line) # JvB added
            self._observe_pre_parsing(line)

            self._state.parser_recursion_level = 0
            commands = self._line_parser.parse(line)
            self._observe_after_parsing(line, commands)

            result = self._execute_commands(commands, line)
            # result of None is considered success, same as result True
            if result is not None and (result is False or result is not True and result != 0):
                #  raise ExecuteError(f'Commands {commands} failed with return code = {result}')
                # only increase the counter (silent error)
                self._error_count = self._error_count + 1
                pass
        except ParseError as e:
            self._register_error(e.format())
        except ExecuteError as e:
            self._register_error(e.format())
        except ServerError as e:
            self._register_error(e.format())
        except KeyboardInterrupt:
            # Catches ctrl-c
            self._register_info("Command execution aborted : '{}'".format(line))
        except SessionTerminate as e:
            self._register_error(e.format())
        except EOFError:
            # Catches ctrl-d
            # We silently ignore this.
            pass
        except Exception as e: # JvB added, includes PathParseError
            self._register_error( str(e) )

    def _execute_commands(self, commands, line):
        try:
            return self._command_executor.execute(commands)
        finally:
            # The observer is always called, even if execution fails
            self._observe_after_executing(line, commands)

    def _register_error(self, error):
        self._error_count = self._error_count + 1
        self._output.print_error_line(error)
        self._observer.on_error(error)

    def _register_info(self, msg):
        self._output.print_info_line(msg)

    def _observe_after_parsing(self, line, commands):
        self._observer.after_parsing(state=self._state, input_line=line, commands=commands)

    def _observe_pre_parsing(self, line):
        self._observer.pre_parsing(state=self._state, input_line=line)

    def _observe_after_executing(self, line, commands):
        self._observer.after_executing(state=self._state, input_line=line, commands=commands)

    @property
    def error_count(self):
        ''' Number of parsing or execution errors encountered .'''
        return self._error_count

    def _must_stop(self):
        if self.error_count and self._stop_on_error:
            return True
        return self._state.is_session_terminated


def _add_decorators(command_reader):
    '''
        Add the decorators that are allowed to transform the input lines before parsing it.

        Note that the decorators are applied top-to-bottom,
        so if we have decorators [A, B] we will return B(A(command_reader))
    '''
    decorators = [
        # If space completion is enabled, will expand all tokens that can uniquely be expanded.
        # e.g. will expand 'i abc s 1' into 'interface abc subinterface 1'.
        SpaceAutoCompleteDecorator,
        # If we encounter an unclosed string, keep reading until it is complete.
        # This allows the user to enter a multiline string, e.g.
        #     description "first
        #       second
        #       last"
        MultilineStringReader,
        # If we encounter an unclosed array, keep reading until it is complete.
        # This allows the user to enter an array on multiple lines, e.g.
        #     array [
        #       value
        #       other-value
        #    ]
        ArrayReader,
    ]

    return functools.reduce(
        lambda result, decorator: decorator(result),
        decorators,
        command_reader)
