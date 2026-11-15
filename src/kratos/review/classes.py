"""The closed table of weakness classes an AI code review looks for (E.7b §3.5).

Each class names:

- its **sinks** -- the dangerous calls, as fully qualified names the slicer resolves through
  a module's own imports (``subprocess.run`` whether written ``subprocess.run``, ``sp.run`` or
  ``run``), or ``*.<method>`` for a method on an object Kratos can't type (``*.execute``);
- whether it is an **execution-like** class (command/code execution, deserialisation) --
  ranked first and the only classes that can be high;
- its **recorders** -- the callables the reproduction harness replaces with a recorder in the
  sandbox, so the real dangerous call is never run, even there. A class with no recorders is
  never reproduced (direct rule or a person's check only).

A new class is a code change with tests, never a setting. The direct rules live in
``kratos.review.rules``; the reproduction templates in ``kratos.review.reproduce``.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WeaknessClass:
    id: str
    label: str                       # plain words, used in titles (never machine text)
    exec_like: bool
    sinks: tuple[str, ...]           # qualified callables, or "*.method"
    recorders: tuple[str, ...]       # "module:attr" the harness replaces; () = never reproduced
    question: str                    # what a person checks when the class can't be confirmed


EXEC = WeaknessClass(
    "exec", "command or code execution", True,
    sinks=("os.system", "os.popen", "os.execl", "os.execlp", "os.execv", "os.execvp", "os.spawnl", "os.spawnlp",
           "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
           "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput",
           "commands.getoutput", "builtins.eval", "builtins.exec"),
    recorders=("os:system", "os:popen", "subprocess:run", "subprocess:call", "subprocess:check_call",
               "subprocess:check_output", "subprocess:Popen", "subprocess:getoutput", "subprocess:getstatusoutput",
               "builtins:eval", "builtins:exec"),
    question="Can a request value reach this command or eval, and is it quoted or checked first?")

DESERIALISE = WeaknessClass(
    "deserialise", "unsafe deserialisation", True,
    sinks=("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "marshal.loads", "marshal.load",
           "shelve.open", "yaml.load", "yaml.unsafe_load", "yaml.full_load", "jsonpickle.decode",
           "dill.loads"),
    recorders=("pickle:loads", "pickle:load", "marshal:loads", "marshal:load"),
    question="Can a request value reach this deserialiser, and does it only ever read trusted data?")

PATH = WeaknessClass(
    "path", "file access with a path from the request", False,
    sinks=("builtins.open", "io.open", "os.open", "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree",
           "shutil.copyfile", "shutil.copy", "shutil.move", "flask.send_file", "codecs.open"),
    recorders=("builtins:open", "io:open", "os:open", "os:remove", "os:unlink", "codecs:open", "flask:send_file"),
    question="Is the path from the request limited to one folder (basename, an allow-list, a check that it "
             "stays inside the folder)?")

SQL = WeaknessClass(
    "sql", "SQL built from request text", False,
    sinks=("*.execute", "*.executemany", "*.executescript", "*.raw"),
    recorders=("sqlite3:connect",),
    question="Is the request value passed as a query parameter rather than formatted into the SQL text?")

TEMPLATE = WeaknessClass(
    "template", "template rendered from request text", False,
    sinks=("flask.render_template_string", "jinja2.Template", "*.from_string", "mako.template.Template"),
    recorders=("flask:render_template_string", "jinja2:Template"),
    question="Does request text become part of the template itself rather than a value passed to it?")

UPLOAD = WeaknessClass(
    "upload", "upload saved under the name the client sent", False,
    sinks=("*.save",),
    recorders=("werkzeug.datastructures:FileStorage.save",),
    question="Is the uploaded file's name cleaned (secure_filename, a generated name) and its type checked?")

NOAUTH = WeaknessClass(
    "noauth", "state-changing route with no login check", False,
    sinks=(),
    recorders=(),
    question="Is this route protected somewhere Kratos can't see (a gateway, middleware, a before-request "
             "hook)?")

CLASSES: dict[str, WeaknessClass] = {c.id: c for c in (EXEC, DESERIALISE, PATH, SQL, TEMPLATE, UPLOAD, NOAUTH)}
CLASS_IDS: tuple[str, ...] = tuple(CLASSES)
EXEC_LIKE: frozenset[str] = frozenset(c.id for c in CLASSES.values() if c.exec_like)

# Method sinks are only taken on these receivers' shapes, to keep "*.save" from meaning every save().
METHOD_SINKS: dict[str, str] = {"execute": "sql", "executemany": "sql", "executescript": "sql", "raw": "sql",
                                "from_string": "template", "save": "upload"}


def class_for_sink(qualified: str) -> str | None:
    """The class whose sink list names this qualified callable (exact names only)."""
    for c in CLASSES.values():
        if qualified in c.sinks:
            return c.id
    return None


def get(class_id: str) -> WeaknessClass:
    return CLASSES[class_id]
