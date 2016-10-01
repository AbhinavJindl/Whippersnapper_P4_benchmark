# -*- coding: utf-8 -*-

import os
import unittest
from subprocess import call, Popen, PIPE
import shlex
import time

from .context import p4gen

class BehaviorTests(unittest.TestCase):
    """Parser test cases."""

    def setUp(self):
        self.assertIsNotNone(os.environ.get('P4BENCHMARK_ROOT'))
        self.assertIsNotNone(os.environ.get('PYTHONPATH'))
        pypath = os.environ.get('PYTHONPATH')
        p4bench = os.environ.get('P4BENCHMARK_ROOT')
        self.assertIn(p4bench, p4bench.split(os.pathsep))
        bmv2 = os.path.join(p4bench, 'behavioral-model')
        self.p4c = os.path.join(p4bench, 'p4c-bm/p4c_bm/__main__.py')
        self.switch_path = os.path.join(bmv2, 'targets/simple_switch/simple_switch')
        self.cli_path = os.path.join(bmv2, 'tools/runtime_CLI.py')


    def tearDown(self):
        cmd = 'sudo pkill lt-simple_swi'
        args = shlex.split(cmd)
        p = Popen(args)
        out, err = p.communicate()
        if out:
            print out
        if err:
            print err
        self.p.wait()
        self.assertIsNotNone(self.p.poll())

    def add_rules(self, json_path, commands, retries):
        if retries > 0:
            cmd = [self.cli_path, '--json', json_path]
            if os.path.isfile(commands):
                with open(commands, "r") as f:
                    p = Popen(cmd, stdin=f, stdout=PIPE, stderr=PIPE)
                    out, err = p.communicate()
                    if out:
                        print out
                        if "Could not" in out:
                            print "Retry in 1 second"
                            sleep(1)
                            return self.add_rules(json_path, port_number, commands, retries-1)
                        elif  "DUPLICATE_ENTRY" in out:
                            pass
                    if err:
                        print err
                        time.sleep(1)
                        return self.add_rules(json_path, port_number, commands, retries-1)

    def test_benchmark_parser_generator(self):
        ret = p4gen.bm_parser.benchmark_parser(10, 4)
        self.assertTrue(ret)
        prog = 'main'
        json_path = 'output/%s.json' % prog
        commands = 'output/commands.txt'
        ret = call([self.p4c, 'output/%s.p4' % prog , '--json', json_path])
        self.assertEqual(ret, 0)
        cmd = 'sudo {0} {1} -i0@veth0 -i1@veth2 -i 2@veth4 --log-console'.format(self.switch_path, json_path)
        print cmd
        args = shlex.split(cmd)
        self.p = Popen(args)
        self.assertIsNone(self.p.poll())
        # wait for the switch to start
        time.sleep(2)
        # insert rules: retry 3 times if not succeed
        self.add_rules(json_path, commands, 3)

        # run_test.py
        cmd = 'sudo python {0} -c 10 -f 4 -n 10'.format('output/run_test.py')
        print cmd
        args = shlex.split(cmd)
        p = Popen(args)
        out, err = p.communicate()
        if out:
            print out
        if err:
            print err
        p.wait()


    # def test_benchmark_pipeline_generator(self):
    #     ret = p4gen.bm_pipeline.benchmark_pipeline(10, 128)
    #     self.assertTrue(ret)
    #     prog = 'main'
    #     ret = call([self.p4c, 'output/%s.p4' % prog , '--json', 'output/%s.json' % prog])
    #     self.assertEqual(ret, 0)

    # def test_benchmark_memory_consumption_generator(self):
    #     ret = p4gen.bm_memory.benchmark_memory(10, 32, 1024)
    #     self.assertTrue(ret)
    #     prog = 'main'
    #     ret = call([self.p4c, 'output/%s.p4' % prog , '--json', 'output/%s.json' % prog])
    #     self.assertEqual(ret, 0)

    # def test_benchmark_add_header_generator(self):
    #     ret = p4gen.bm_modification.benchmark_modification(10, 4, 'add')
    #     self.assertTrue(ret)
    #     prog = 'main'
    #     ret = call([self.p4c, 'output/%s.p4' % prog , '--json', 'output/%s.json' % prog])
    #     self.assertEqual(ret, 0)

    # def test_benchmark_remove_header_generator(self):
    #     ret = p4gen.bm_modification.benchmark_modification(10, 4, 'rm')
    #     self.assertTrue(ret)
    #     prog = 'main'
    #     ret = call([self.p4c, 'output/%s.p4' % prog , '--json', 'output/%s.json' % prog])
    #     self.assertEqual(ret, 0)

    # def test_benchmark_modify_header_generator(self):
    #     ret = p4gen.bm_modification.benchmark_modification(10, 4, 'mod')
    #     self.assertTrue(ret)
    #     prog = 'main'
    #     ret = call([self.p4c, 'output/%s.p4' % prog , '--json', 'output/%s.json' % prog])
    #     self.assertEqual(ret, 0)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(BehaviorTests)
    unittest.TextTestRunner(verbosity=2).run(suite)