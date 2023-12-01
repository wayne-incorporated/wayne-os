#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Unit tests for the TPM 2.0 code generator."""

from __future__ import print_function

import io
import unittest

import generator


class TestGenerators(unittest.TestCase):
    """Test generator classes."""

    def testTypedef(self):
        """Test generation of typedefs and dependencies."""
        typedef = generator.Typedef("int", "INT")
        defined_types = set(["int"])
        typemap = {}
        out_file = io.StringIO()
        # Expect this to just write the typedef.
        typedef.OutputForward(out_file, defined_types, typemap)
        # Expect this to know it has already been written.
        typedef.Output(out_file, defined_types, typemap)
        self.assertEqual(out_file.getvalue(), "typedef int INT;\n")
        self.assertIn("INT", defined_types)
        typedef2 = generator.Typedef("TYPE1", "TYPE2")
        typemap = {"TYPE1": generator.Structure("TYPE1", False)}
        defined_types = set([])
        out_file2 = io.StringIO()
        # Expect this to write first TYPE1 forward then TYPE2 typedef.
        typedef2.Output(out_file2, defined_types, typemap)
        output_re = r"struct TYPE1;\s+typedef TYPE1 TYPE2;\s+"
        self.assertRegex(out_file2.getvalue(), output_re)
        self.assertIn("TYPE2", defined_types)
        out_file.close()
        out_file2.close()

    def testTypedefSerialize(self):
        """Test generation of serialization code for typedefs."""
        serialized_types = set(["int"])
        typedef = generator.Typedef("int", "INT")
        typedef2 = generator.Typedef("INT", "INT2")
        typemap = {"INT": typedef}
        out_file = io.StringIO()
        typedef2.OutputSerialize(out_file, serialized_types, typemap)
        self.assertIn("INT", serialized_types)
        self.assertIn("INT2", serialized_types)
        out_file.close()

    def testConstant(self):
        """Test generation of constant definitions and type dependencies."""
        constant = generator.Constant("INT", "test", "1")
        typemap = {"INT": generator.Structure("INT", False)}
        defined_types = set([])
        out_file = io.StringIO()
        constant.Output(out_file, defined_types, typemap)
        output_re = r"struct INT;\s+constexpr INT test = 1;\s+"
        self.assertRegex(out_file.getvalue(), output_re)
        out_file.close()

    def testStructure(self):
        """Test generation of structure declarations and field dependencies."""
        struct = generator.Structure("STRUCT", False)
        struct.AddField("int", "i")
        struct.AddDependency("DEPEND")
        union = generator.Structure("UNION", True)
        union.AddField("STRUCT", "inner")
        depend = generator.Structure("DEPEND", False)
        defined_types = set(["int"])
        out_file = io.StringIO()
        typemap = {"STRUCT": struct, "DEPEND": depend}
        # Only output |union|, this will test the dependency logic.
        union.OutputForward(out_file, defined_types, typemap)
        union.OutputForward(out_file, defined_types, typemap)
        union.Output(out_file, defined_types, typemap)
        output_re = r"union UNION;\s+struct DEPEND {\s+};\s+"
        output_re += r"struct STRUCT {\s+int i = {};\s+};\s+"
        output_re += r"union UNION {\s+STRUCT inner;\s+};\s+"
        self.assertRegex(out_file.getvalue(), output_re)
        for t in ("STRUCT", "DEPEND", "UNION"):
            self.assertIn(t, defined_types)
        # Test serialize / parse code generation.
        out_file.close()

    def testStructSerialize(self):
        """Test generation of serialization code for typedefs."""
        serialized_types = set(["int", "FOO", "BAR", "TPMI_ALG_SYM_OBJECT"])
        struct = generator.Structure("TEST_STRUCT", False)
        struct.fields = [
            ("TPMI_ALG_SYM_OBJECT", "selector"),
            ("TPMU_SYM_MODE", "mode"),
            ("int", "sizeOfFoo"),
            ("int", "foo[FOO_MAX]"),
        ]
        # Choose TPMU_SYM_MODE because it exists in the selectors definition and it
        # has few fields.
        union = generator.Structure("TPMU_SYM_MODE", True)
        union.fields = [("FOO", "aes"), ("BAR", "sm4")]
        typemap = {"TPMU_SYM_MODE": union}
        out_file = io.StringIO()
        struct.OutputSerialize(out_file, serialized_types, typemap)
        self.assertIn("TPMU_SYM_MODE", serialized_types)
        self.assertIn("TEST_STRUCT", serialized_types)
        out_file.close()

    def testDefine(self):
        """Test generation of preprocessor defines."""
        define = generator.Define("name", "value")
        out_file = io.StringIO()
        define.Output(out_file)
        output_re = r"#if !defined\(name\)\s+#define name value\s+#endif\s+"
        self.assertRegex(out_file.getvalue(), output_re)
        out_file.close()

    def _MakeArg(self, arg_type, arg_name):
        return {
            "type": arg_type,
            "name": arg_name,
            "command_code": None,
            "description": None,
        }

    def testCommand(self):
        """Test generation of command methods and callbacks."""
        command = generator.Command("TPM2_Test")
        command.request_args = [self._MakeArg("int", "input")]
        command.response_args = [self._MakeArg("char", "output")]
        out_file = io.StringIO()
        command.OutputDeclarations(out_file)
        expected_callback = """typedef base::OnceCallback<void(
      TPM_RC response_code,
      const char& output)> TestResponse;"""
        self.assertIn(expected_callback, out_file.getvalue())
        expected_serialize = """static TPM_RC SerializeCommand_Test(
      const int& input,
      std::string* serialized_command,
      AuthorizationDelegate* authorization_delegate);"""
        self.assertIn(expected_serialize, out_file.getvalue())
        expected_parse = """static TPM_RC ParseResponse_Test(
      const std::string& response,
      char* output,
      AuthorizationDelegate* authorization_delegate);"""
        self.assertIn(expected_parse, out_file.getvalue())
        expected_async = """virtual void Test(
      const int& input,
      AuthorizationDelegate* authorization_delegate,
      TestResponse callback);"""
        self.assertIn(expected_async, out_file.getvalue())
        expected_sync = """virtual TPM_RC TestSync(
      const int& input,
      char* output,
      AuthorizationDelegate* authorization_delegate);"""
        self.assertIn(expected_sync, out_file.getvalue())
        out_file.close()


class TestParsers(unittest.TestCase):
    """Test parser classes."""

    FAKE_TYPEDEF = "_BEGIN_TYPES\n_OLD_TYPE type1\n_NEW_TYPE type2\n_END\n"
    FAKE_CONSTANT = (
        "_BEGIN_CONSTANTS\n_CONSTANTS (base_type) const_type\n"
        "_TYPE base_type\n_NAME const_name\n_VALUE const_value\n"
        "_END\n"
    )
    FAKE_STRUCTURE = (
        "_BEGIN_STRUCTURES\n_STRUCTURE struct_type\n"
        "_TYPE field_type\n"
        "_NAME field_name[sizeof(depend_type)]\n_END\n"
    )
    FAKE_DEFINE = "_BEGIN_DEFINES\n_NAME define_name\n_VALUE define_value\n_END"
    FAKE_COMMAND = (
        "_BEGIN\n_INPUT_START TPM2_Test\n"
        "_TYPE UINT32\n_NAME commandSize\n"
        "_TYPE TPM_CC\n_NAME commandCode\n_COMMENT TPM_CC_Test\n"
        "_TYPE UINT16\n_NAME input\n"
        "_OUTPUT_START TPM2_Test\n_END\n"
    )

    def testStructureParserWithBadData(self):
        """Test the structure parser with invalid data."""
        input_data = "bad_data"
        in_file = io.StringIO(input_data)
        parser = generator.StructureParser(in_file)
        types, constants, structs, defines, typemap = parser.Parse()
        self.assertIsNotNone(types)
        self.assertIsNotNone(constants)
        self.assertIsNotNone(structs)
        self.assertIsNotNone(defines)
        self.assertIsNotNone(typemap)

    def testStructureParser(self):
        """Test the structure parser with valid data."""
        input_data = (
            self.FAKE_TYPEDEF
            + self.FAKE_CONSTANT
            + self.FAKE_STRUCTURE
            + self.FAKE_DEFINE
        )
        in_file = io.StringIO(input_data)
        parser = generator.StructureParser(in_file)
        types, constants, structs, defines, typemap = parser.Parse()
        # Be flexible on these counts because the parser may add special cases.
        self.assertGreaterEqual(len(types), 2)
        self.assertGreaterEqual(len(constants), 1)
        self.assertGreaterEqual(len(structs), 1)
        self.assertGreaterEqual(len(defines), 1)
        self.assertGreaterEqual(len(typemap), 3)
        self.assertEqual(types[0].old_type, "type1")
        self.assertEqual(types[0].new_type, "type2")
        self.assertEqual(types[1].old_type, "base_type")
        self.assertEqual(types[1].new_type, "const_type")
        self.assertEqual(constants[0].const_type, "const_type")
        self.assertEqual(constants[0].name, "const_name")
        self.assertEqual(constants[0].value, "const_value")
        self.assertEqual(structs[0].name, "struct_type")
        self.assertEqual(structs[0].is_union, False)
        self.assertEqual(len(structs[0].fields), 1)
        self.assertEqual(structs[0].fields[0][0], "field_type")
        self.assertEqual(
            structs[0].fields[0][1], "field_name[sizeof(depend_type)]"
        )
        self.assertEqual(len(structs[0].depends_on), 1)
        self.assertEqual(structs[0].depends_on[0], "depend_type")
        self.assertEqual(defines[0].name, "define_name")
        self.assertEqual(defines[0].value, "define_value")

    def testCommandParserWithBadData(self):
        """Test the command parser with invalid data."""
        input_data = "bad_data"
        in_file = io.StringIO(input_data)
        parser = generator.CommandParser(in_file)
        commands = parser.Parse()
        self.assertIsNotNone(commands)

    def testCommandParser(self):
        """Test the command parser with valid data."""
        input_data = self.FAKE_COMMAND
        in_file = io.StringIO(input_data)
        parser = generator.CommandParser(in_file)
        commands = parser.Parse()
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0].name, "TPM2_Test")
        self.assertEqual(commands[0].command_code, "TPM_CC_Test")
        # We expect the 'commandSize' and 'commandCode' args to be filtered out.
        self.assertEqual(len(commands[0].request_args), 1)
        self.assertEqual(commands[0].request_args[0]["type"], "UINT16")
        self.assertEqual(commands[0].request_args[0]["name"], "input")
        self.assertIsNotNone(commands[0].response_args)
        self.assertFalse(commands[0].response_args)


if __name__ == "__main__":
    unittest.main()
