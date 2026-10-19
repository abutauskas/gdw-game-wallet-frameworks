// Deterministic JSON value with canonical (JCS-style) encoding.
//
// We avoid System.Text.Json's object model because canonical ordering and
// integer-only rules are easier to guarantee on our own small tree. Parsing
// still uses System.Text.Json's reader for correctness of lexing.
//
// SPDX-License-Identifier: CC-BY-4.0

using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Eudi.GameWallet;

public enum JsonKind { Null, Bool, Int, String, Array, Object }

/// <summary>
/// A JSON value that always serialises to canonical GDW form (sorted keys, no
/// whitespace, integers only). Object keys are kept in a sorted dictionary so
/// ordering is deterministic for free.
/// </summary>
public sealed class GdwJson
{
    public JsonKind Kind { get; private set; }
    private bool _bool;
    private long _int;
    private string _string = "";
    private List<GdwJson> _array = new();
    private SortedDictionary<string, GdwJson> _object = new(StringComparer.Ordinal);

    public static GdwJson Null() => new() { Kind = JsonKind.Null };
    public static GdwJson Bool(bool v) => new() { Kind = JsonKind.Bool, _bool = v };
    public static GdwJson Int(long v) => new() { Kind = JsonKind.Int, _int = v };
    public static GdwJson Str(string v) => new() { Kind = JsonKind.String, _string = v };
    public static GdwJson Array() => new() { Kind = JsonKind.Array };
    public static GdwJson Object() => new() { Kind = JsonKind.Object };

    public static GdwJson ArrayOf(params GdwJson[] items)
    {
        var a = Array();
        a._array.AddRange(items);
        return a;
    }

    public static GdwJson ArrayOfStrings(IEnumerable<string> values)
    {
        var a = Array();
        foreach (var v in values) a._array.Add(Str(v));
        return a;
    }

    public IReadOnlyList<GdwJson> Items => _array;
    public IReadOnlyDictionary<string, GdwJson> Entries => _object;

    public GdwJson this[string key]
    {
        get => _object[key];
        set => _object[key] = value;
    }

    public GdwJson Add(GdwJson value) { _array.Add(value); return this; }

    public bool Has(string key) => _object.ContainsKey(key);

    public GdwJson? Get(string key) => _object.TryGetValue(key, out var v) ? v : null;

    public bool IsString => Kind == JsonKind.String;
    public bool IsArray => Kind == JsonKind.Array;
    public bool IsObject => Kind == JsonKind.Object;

    public string AsString(string fallback = "") => Kind == JsonKind.String ? _string : fallback;
    public long AsInt(long fallback = 0) => Kind == JsonKind.Int ? _int : fallback;
    public bool AsBool(bool fallback = false) => Kind == JsonKind.Bool ? _bool : fallback;

    /// <summary>Canonical serialisation. Throws on floats/out-of-range ints.</summary>
    public string Canonical()
    {
        var sb = new StringBuilder();
        Write(sb);
        return sb.ToString();
    }

    private void Write(StringBuilder sb)
    {
        switch (Kind)
        {
            case JsonKind.Null: sb.Append("null"); break;
            case JsonKind.Bool: sb.Append(_bool ? "true" : "false"); break;
            case JsonKind.Int: sb.Append(_int.ToString(CultureInfo.InvariantCulture)); break;
            case JsonKind.String: WriteString(sb, _string); break;
            case JsonKind.Array:
                sb.Append('[');
                for (int i = 0; i < _array.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    _array[i].Write(sb);
                }
                sb.Append(']');
                break;
            case JsonKind.Object:
                sb.Append('{');
                bool first = true;
                foreach (var kv in _object) // SortedDictionary → ascending ordinal
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteString(sb, kv.Key);
                    sb.Append(':');
                    kv.Value.Write(sb);
                }
                sb.Append('}');
                break;
        }
    }

    private static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\t': sb.Append("\\t"); break;
                case '\n': sb.Append("\\n"); break;
                case '\f': sb.Append("\\f"); break;
                case '\r': sb.Append("\\r"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c); // raw UTF-16; string is written as UTF-8 by caller
                    break;
            }
        }
        sb.Append('"');
    }

    // ---- parsing ----------------------------------------------------------

    public static GdwJson Parse(string text)
    {
        var reader = new Utf8JsonReader(new ReadOnlySpan<byte>(Encoding.UTF8.GetBytes(text)));
        if (!reader.Read()) throw new GdwException(GdwErrors.Malformed);
        var value = ParseValue(ref reader);
        return value;
    }

    private static GdwJson ParseValue(ref Utf8JsonReader reader)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Null: return Null();
            case JsonTokenType.True: return Bool(true);
            case JsonTokenType.False: return Bool(false);
            case JsonTokenType.Number:
                if (reader.TryGetInt64(out long i)) return Int(i);
                throw new GdwException(GdwErrors.Malformed); // floats forbidden
            case JsonTokenType.String: return Str(reader.GetString() ?? "");
            case JsonTokenType.StartArray:
            {
                var arr = Array();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                    arr._array.Add(ParseValue(ref reader));
                return arr;
            }
            case JsonTokenType.StartObject:
            {
                var obj = Object();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
                {
                    if (reader.TokenType != JsonTokenType.PropertyName)
                        throw new GdwException(GdwErrors.Malformed);
                    string key = reader.GetString() ?? "";
                    if (!reader.Read()) throw new GdwException(GdwErrors.Malformed);
                    obj._object[key] = ParseValue(ref reader);
                }
                return obj;
            }
            default:
                throw new GdwException(GdwErrors.Malformed);
        }
    }
}
