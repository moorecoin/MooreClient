/*!
 * jquery javascript library v1.10.2
 * http://jquery.com/
 *
 * includes sizzle.js
 * http://sizzlejs.com/
 *
 * copyright 2005, 2013 jquery foundation, inc. and other contributors
 * released under the mit license
 * http://jquery.org/license
 *
 * date: 2013-07-03t13:48z
 */
(function( window, undefined ) {

// can't do this because several apps including asp.net trace
// the stack via arguments.caller.callee and firefox dies if
// you try to trace through "use strict" call chains. (#13335)
// support: firefox 18+
//"use strict";
    var
    // the deferred used on dom ready
        readylist,

    // a central reference to the root jquery(document)
        rootjquery,

    // support: ie<10
    // for `typeof xmlnode.method` instead of `xmlnode.method !== undefined`
        core_strundefined = typeof undefined,

    // use the correct document accordingly with window argument (sandbox)
        location = window.location,
        document = window.document,
        docelem = document.documentelement,

    // map over jquery in case of overwrite
        _jquery = window.jquery,

    // map over the $ in case of overwrite
        _$ = window.$,

    // [[class]] -> type pairs
        class2type = {},

    // list of deleted data cache ids, so we can reuse them
        core_deletedids = [],

        core_version = "1.10.2",

    // save a reference to some core methods
        core_concat = core_deletedids.concat,
        core_push = core_deletedids.push,
        core_slice = core_deletedids.slice,
        core_indexof = core_deletedids.indexof,
        core_tostring = class2type.tostring,
        core_hasown = class2type.hasownproperty,
        core_trim = core_version.trim,

    // define a local copy of jquery
        jquery = function( selector, context ) {
            // the jquery object is actually just the init constructor 'enhanced'
            return new jquery.fn.init( selector, context, rootjquery );
        },

    // used for matching numbers
        core_pnum = /[+-]?(?:\d*\.|)\d+(?:[ee][+-]?\d+|)/.source,

    // used for splitting on whitespace
        core_rnotwhite = /\s+/g,

    // make sure we trim bom and nbsp (here's looking at you, safari 5.0 and ie)
        rtrim = /^[\s\ufeff\xa0]+|[\s\ufeff\xa0]+$/g,

    // a simple way to check for html strings
    // prioritize #id over <tag> to avoid xss via location.hash (#9521)
    // strict html recognition (#11290: must start with <)
        rquickexpr = /^(?:\s*(<[\w\w]+>)[^>]*|#([\w-]*))$/,

    // match a standalone tag
        rsingletag = /^<(\w+)\s*\/?>(?:<\/\1>|)$/,

    // json regexp
        rvalidchars = /^[\],:{}\s]*$/,
        rvalidbraces = /(?:^|:|,)(?:\s*\[)+/g,
        rvalidescape = /\\(?:["\\\/bfnrt]|u[\da-fa-f]{4})/g,
        rvalidtokens = /"[^"\\\r\n]*"|true|false|null|-?(?:\d+\.|)\d+(?:[ee][+-]?\d+|)/g,

    // matches dashed string for camelizing
        rmsprefix = /^-ms-/,
        rdashalpha = /-([\da-z])/gi,

    // used by jquery.camelcase as callback to replace()
        fcamelcase = function( all, letter ) {
            return letter.touppercase();
        },

    // the ready event handler
        completed = function( event ) {

            // readystate === "complete" is good enough for us to call the dom ready in oldie
            if ( document.addeventlistener || event.type === "load" || document.readystate === "complete" ) {
                detach();
                jquery.ready();
            }
        },
    // clean-up method for dom ready events
        detach = function() {
            if ( document.addeventlistener ) {
                document.removeeventlistener( "domcontentloaded", completed, false );
                window.removeeventlistener( "load", completed, false );

            } else {
                document.detachevent( "onreadystatechange", completed );
                window.detachevent( "onload", completed );
            }
        };

    jquery.fn = jquery.prototype = {
        // the current version of jquery being used
        jquery: core_version,

        constructor: jquery,
        init: function( selector, context, rootjquery ) {
            var match, elem;

            // handle: $(""), $(null), $(undefined), $(false)
            if ( !selector ) {
                return this;
            }

            // handle html strings
            if ( typeof selector === "string" ) {
                if ( selector.charat(0) === "<" && selector.charat( selector.length - 1 ) === ">" && selector.length >= 3 ) {
                    // assume that strings that start and end with <> are html and skip the regex check
                    match = [ null, selector, null ];

                } else {
                    match = rquickexpr.exec( selector );
                }

                // match html or make sure no context is specified for #id
                if ( match && (match[1] || !context) ) {

                    // handle: $(html) -> $(array)
                    if ( match[1] ) {
                        context = context instanceof jquery ? context[0] : context;

                        // scripts is true for back-compat
                        jquery.merge( this, jquery.parsehtml(
                            match[1],
                                context && context.nodetype ? context.ownerdocument || context : document,
                            true
                        ) );

                        // handle: $(html, props)
                        if ( rsingletag.test( match[1] ) && jquery.isplainobject( context ) ) {
                            for ( match in context ) {
                                // properties of context are called as methods if possible
                                if ( jquery.isfunction( this[ match ] ) ) {
                                    this[ match ]( context[ match ] );

                                    // ...and otherwise set as attributes
                                } else {
                                    this.attr( match, context[ match ] );
                                }
                            }
                        }

                        return this;

                        // handle: $(#id)
                    } else {
                        elem = document.getelementbyid( match[2] );

                        // check parentnode to catch when blackberry 4.6 returns
                        // nodes that are no longer in the document #6963
                        if ( elem && elem.parentnode ) {
                            // handle the case where ie and opera return items
                            // by name instead of id
                            if ( elem.id !== match[2] ) {
                                return rootjquery.find( selector );
                            }

                            // otherwise, we inject the element directly into the jquery object
                            this.length = 1;
                            this[0] = elem;
                        }

                        this.context = document;
                        this.selector = selector;
                        return this;
                    }

                    // handle: $(expr, $(...))
                } else if ( !context || context.jquery ) {
                    return ( context || rootjquery ).find( selector );

                    // handle: $(expr, context)
                    // (which is just equivalent to: $(context).find(expr)
                } else {
                    return this.constructor( context ).find( selector );
                }

                // handle: $(domelement)
            } else if ( selector.nodetype ) {
                this.context = this[0] = selector;
                this.length = 1;
                return this;

                // handle: $(function)
                // shortcut for document ready
            } else if ( jquery.isfunction( selector ) ) {
                return rootjquery.ready( selector );
            }

            if ( selector.selector !== undefined ) {
                this.selector = selector.selector;
                this.context = selector.context;
            }

            return jquery.makearray( selector, this );
        },

        // start with an empty selector
        selector: "",

        // the default length of a jquery object is 0
        length: 0,

        toarray: function() {
            return core_slice.call( this );
        },

        // get the nth element in the matched element set or
        // get the whole matched element set as a clean array
        get: function( num ) {
            return num == null ?

                // return a 'clean' array
                this.toarray() :

                // return just the object
                ( num < 0 ? this[ this.length + num ] : this[ num ] );
        },

        // take an array of elements and push it onto the stack
        // (returning the new matched element set)
        pushstack: function( elems ) {

            // build a new jquery matched element set
            var ret = jquery.merge( this.constructor(), elems );

            // add the old object onto the stack (as a reference)
            ret.prevobject = this;
            ret.context = this.context;

            // return the newly-formed element set
            return ret;
        },

        // execute a callback for every element in the matched set.
        // (you can seed the arguments with an array of args, but this is
        // only used internally.)
        each: function( callback, args ) {
            return jquery.each( this, callback, args );
        },

        ready: function( fn ) {
            // add the callback
            jquery.ready.promise().done( fn );

            return this;
        },

        slice: function() {
            return this.pushstack( core_slice.apply( this, arguments ) );
        },

        first: function() {
            return this.eq( 0 );
        },

        last: function() {
            return this.eq( -1 );
        },

        eq: function( i ) {
            var len = this.length,
                j = +i + ( i < 0 ? len : 0 );
            return this.pushstack( j >= 0 && j < len ? [ this[j] ] : [] );
        },

        map: function( callback ) {
            return this.pushstack( jquery.map(this, function( elem, i ) {
                return callback.call( elem, i, elem );
            }));
        },

        end: function() {
            return this.prevobject || this.constructor(null);
        },

        // for internal use only.
        // behaves like an array's method, not like a jquery method.
        push: core_push,
        sort: [].sort,
        splice: [].splice
    };

// give the init function the jquery prototype for later instantiation
    jquery.fn.init.prototype = jquery.fn;

    jquery.extend = jquery.fn.extend = function() {
        var src, copyisarray, copy, name, options, clone,
            target = arguments[0] || {},
            i = 1,
            length = arguments.length,
            deep = false;

        // handle a deep copy situation
        if ( typeof target === "boolean" ) {
            deep = target;
            target = arguments[1] || {};
            // skip the boolean and the target
            i = 2;
        }

        // handle case when target is a string or something (possible in deep copy)
        if ( typeof target !== "object" && !jquery.isfunction(target) ) {
            target = {};
        }

        // extend jquery itself if only one argument is passed
        if ( length === i ) {
            target = this;
            --i;
        }

        for ( ; i < length; i++ ) {
            // only deal with non-null/undefined values
            if ( (options = arguments[ i ]) != null ) {
                // extend the base object
                for ( name in options ) {
                    src = target[ name ];
                    copy = options[ name ];

                    // prevent never-ending loop
                    if ( target === copy ) {
                        continue;
                    }

                    // recurse if we're merging plain objects or arrays
                    if ( deep && copy && ( jquery.isplainobject(copy) || (copyisarray = jquery.isarray(copy)) ) ) {
                        if ( copyisarray ) {
                            copyisarray = false;
                            clone = src && jquery.isarray(src) ? src : [];

                        } else {
                            clone = src && jquery.isplainobject(src) ? src : {};
                        }

                        // never move original objects, clone them
                        target[ name ] = jquery.extend( deep, clone, copy );

                        // don't bring in undefined values
                    } else if ( copy !== undefined ) {
                        target[ name ] = copy;
                    }
                }
            }
        }

        // return the modified object
        return target;
    };

    jquery.extend({
        // unique for each copy of jquery on the page
        // non-digits removed to match rinlinejquery
        expando: "jquery" + ( core_version + math.random() ).replace( /\d/g, "" ),

        noconflict: function( deep ) {
            if ( window.$ === jquery ) {
                window.$ = _$;
            }

            if ( deep && window.jquery === jquery ) {
                window.jquery = _jquery;
            }

            return jquery;
        },

        // is the dom ready to be used? set to true once it occurs.
        isready: false,

        // a counter to track how many items to wait for before
        // the ready event fires. see #6781
        readywait: 1,

        // hold (or release) the ready event
        holdready: function( hold ) {
            if ( hold ) {
                jquery.readywait++;
            } else {
                jquery.ready( true );
            }
        },

        // handle when the dom is ready
        ready: function( wait ) {

            // abort if there are pending holds or we're already ready
            if ( wait === true ? --jquery.readywait : jquery.isready ) {
                return;
            }

            // make sure body exists, at least, in case ie gets a little overzealous (ticket #5443).
            if ( !document.body ) {
                return settimeout( jquery.ready );
            }

            // remember that the dom is ready
            jquery.isready = true;

            // if a normal dom ready event fired, decrement, and wait if need be
            if ( wait !== true && --jquery.readywait > 0 ) {
                return;
            }

            // if there are functions bound, to execute
            readylist.resolvewith( document, [ jquery ] );

            // trigger any bound ready events
            if ( jquery.fn.trigger ) {
                jquery( document ).trigger("ready").off("ready");
            }
        },

        // see test/unit/core.js for details concerning isfunction.
        // since version 1.3, dom methods and functions like alert
        // aren't supported. they return false on ie (#2968).
        isfunction: function( obj ) {
            return jquery.type(obj) === "function";
        },

        isarray: array.isarray || function( obj ) {
            return jquery.type(obj) === "array";
        },

        iswindow: function( obj ) {
            /* jshint eqeqeq: false */
            return obj != null && obj == obj.window;
        },

        isnumeric: function( obj ) {
            return !isnan( parsefloat(obj) ) && isfinite( obj );
        },

        type: function( obj ) {
            if ( obj == null ) {
                return string( obj );
            }
            return typeof obj === "object" || typeof obj === "function" ?
                class2type[ core_tostring.call(obj) ] || "object" :
                typeof obj;
        },

        isplainobject: function( obj ) {
            var key;

            // must be an object.
            // because of ie, we also have to check the presence of the constructor property.
            // make sure that dom nodes and window objects don't pass through, as well
            if ( !obj || jquery.type(obj) !== "object" || obj.nodetype || jquery.iswindow( obj ) ) {
                return false;
            }

            try {
                // not own constructor property must be object
                if ( obj.constructor &&
                    !core_hasown.call(obj, "constructor") &&
                    !core_hasown.call(obj.constructor.prototype, "isprototypeof") ) {
                    return false;
                }
            } catch ( e ) {
                // ie8,9 will throw exceptions on certain host objects #9897
                return false;
            }

            // support: ie<9
            // handle iteration over inherited properties before own properties.
            if ( jquery.support.ownlast ) {
                for ( key in obj ) {
                    return core_hasown.call( obj, key );
                }
            }

            // own properties are enumerated firstly, so to speed up,
            // if last one is own, then all properties are own.
            for ( key in obj ) {}

            return key === undefined || core_hasown.call( obj, key );
        },

        isemptyobject: function( obj ) {
            var name;
            for ( name in obj ) {
                return false;
            }
            return true;
        },

        error: function( msg ) {
            throw new error( msg );
        },

        // data: string of html
        // context (optional): if specified, the fragment will be created in this context, defaults to document
        // keepscripts (optional): if true, will include scripts passed in the html string
        parsehtml: function( data, context, keepscripts ) {
            if ( !data || typeof data !== "string" ) {
                return null;
            }
            if ( typeof context === "boolean" ) {
                keepscripts = context;
                context = false;
            }
            context = context || document;

            var parsed = rsingletag.exec( data ),
                scripts = !keepscripts && [];

            // single tag
            if ( parsed ) {
                return [ context.createelement( parsed[1] ) ];
            }

            parsed = jquery.buildfragment( [ data ], context, scripts );
            if ( scripts ) {
                jquery( scripts ).remove();
            }
            return jquery.merge( [], parsed.childnodes );
        },

        parsejson: function( data ) {
            // attempt to parse using the native json parser first
            if ( window.json && window.json.parse ) {
                return window.json.parse( data );
            }

            if ( data === null ) {
                return data;
            }

            if ( typeof data === "string" ) {

                // make sure leading/trailing whitespace is removed (ie can't handle it)
                data = jquery.trim( data );

                if ( data ) {
                    // make sure the incoming data is actual json
                    // logic borrowed from http://json.org/json2.js
                    if ( rvalidchars.test( data.replace( rvalidescape, "@" )
                        .replace( rvalidtokens, "]" )
                        .replace( rvalidbraces, "")) ) {

                        return ( new function( "return " + data ) )();
                    }
                }
            }

            jquery.error( "invalid json: " + data );
        },

        // cross-browser xml parsing
        parsexml: function( data ) {
            var xml, tmp;
            if ( !data || typeof data !== "string" ) {
                return null;
            }
            try {
                if ( window.domparser ) { // standard
                    tmp = new domparser();
                    xml = tmp.parsefromstring( data , "text/xml" );
                } else { // ie
                    xml = new activexobject( "microsoft.xmldom" );
                    xml.async = "false";
                    xml.loadxml( data );
                }
            } catch( e ) {
                xml = undefined;
            }
            if ( !xml || !xml.documentelement || xml.getelementsbytagname( "parsererror" ).length ) {
                jquery.error( "invalid xml: " + data );
            }
            return xml;
        },

        noop: function() {},

        // evaluates a script in a global context
        // workarounds based on findings by jim driscoll
        // http://weblogs.java.net/blog/driscoll/archive/2009/09/08/eval-javascript-global-context
        globaleval: function( data ) {
            if ( data && jquery.trim( data ) ) {
                // we use execscript on internet explorer
                // we use an anonymous function so that context is window
                // rather than jquery in firefox
                ( window.execscript || function( data ) {
                    window[ "eval" ].call( window, data );
                } )( data );
            }
        },

        // convert dashed to camelcase; used by the css and data modules
        // microsoft forgot to hump their vendor prefix (#9572)
        camelcase: function( string ) {
            return string.replace( rmsprefix, "ms-" ).replace( rdashalpha, fcamelcase );
        },

        nodename: function( elem, name ) {
            return elem.nodename && elem.nodename.tolowercase() === name.tolowercase();
        },

        // args is for internal usage only
        each: function( obj, callback, args ) {
            var value,
                i = 0,
                length = obj.length,
                isarray = isarraylike( obj );

            if ( args ) {
                if ( isarray ) {
                    for ( ; i < length; i++ ) {
                        value = callback.apply( obj[ i ], args );

                        if ( value === false ) {
                            break;
                        }
                    }
                } else {
                    for ( i in obj ) {
                        value = callback.apply( obj[ i ], args );

                        if ( value === false ) {
                            break;
                        }
                    }
                }

                // a special, fast, case for the most common use of each
            } else {
                if ( isarray ) {
                    for ( ; i < length; i++ ) {
                        value = callback.call( obj[ i ], i, obj[ i ] );

                        if ( value === false ) {
                            break;
                        }
                    }
                } else {
                    for ( i in obj ) {
                        value = callback.call( obj[ i ], i, obj[ i ] );

                        if ( value === false ) {
                            break;
                        }
                    }
                }
            }

            return obj;
        },

        // use native string.trim function wherever possible
        trim: core_trim && !core_trim.call("\ufeff\xa0") ?
            function( text ) {
                return text == null ?
                    "" :
                    core_trim.call( text );
            } :

            // otherwise use our own trimming functionality
            function( text ) {
                return text == null ?
                    "" :
                    ( text + "" ).replace( rtrim, "" );
            },

        // results is for internal usage only
        makearray: function( arr, results ) {
            var ret = results || [];

            if ( arr != null ) {
                if ( isarraylike( object(arr) ) ) {
                    jquery.merge( ret,
                            typeof arr === "string" ?
                            [ arr ] : arr
                    );
                } else {
                    core_push.call( ret, arr );
                }
            }

            return ret;
        },

        inarray: function( elem, arr, i ) {
            var len;

            if ( arr ) {
                if ( core_indexof ) {
                    return core_indexof.call( arr, elem, i );
                }

                len = arr.length;
                i = i ? i < 0 ? math.max( 0, len + i ) : i : 0;

                for ( ; i < len; i++ ) {
                    // skip accessing in sparse arrays
                    if ( i in arr && arr[ i ] === elem ) {
                        return i;
                    }
                }
            }

            return -1;
        },

        merge: function( first, second ) {
            var l = second.length,
                i = first.length,
                j = 0;

            if ( typeof l === "number" ) {
                for ( ; j < l; j++ ) {
                    first[ i++ ] = second[ j ];
                }
            } else {
                while ( second[j] !== undefined ) {
                    first[ i++ ] = second[ j++ ];
                }
            }

            first.length = i;

            return first;
        },

        grep: function( elems, callback, inv ) {
            var retval,
                ret = [],
                i = 0,
                length = elems.length;
            inv = !!inv;

            // go through the array, only saving the items
            // that pass the validator function
            for ( ; i < length; i++ ) {
                retval = !!callback( elems[ i ], i );
                if ( inv !== retval ) {
                    ret.push( elems[ i ] );
                }
            }

            return ret;
        },

        // arg is for internal usage only
        map: function( elems, callback, arg ) {
            var value,
                i = 0,
                length = elems.length,
                isarray = isarraylike( elems ),
                ret = [];

            // go through the array, translating each of the items to their
            if ( isarray ) {
                for ( ; i < length; i++ ) {
                    value = callback( elems[ i ], i, arg );

                    if ( value != null ) {
                        ret[ ret.length ] = value;
                    }
                }

                // go through every key on the object,
            } else {
                for ( i in elems ) {
                    value = callback( elems[ i ], i, arg );

                    if ( value != null ) {
                        ret[ ret.length ] = value;
                    }
                }
            }

            // flatten any nested arrays
            return core_concat.apply( [], ret );
        },

        // a global guid counter for objects
        guid: 1,

        // bind a function to a context, optionally partially applying any
        // arguments.
        proxy: function( fn, context ) {
            var args, proxy, tmp;

            if ( typeof context === "string" ) {
                tmp = fn[ context ];
                context = fn;
                fn = tmp;
            }

            // quick check to determine if target is callable, in the spec
            // this throws a typeerror, but we will just return undefined.
            if ( !jquery.isfunction( fn ) ) {
                return undefined;
            }

            // simulated bind
            args = core_slice.call( arguments, 2 );
            proxy = function() {
                return fn.apply( context || this, args.concat( core_slice.call( arguments ) ) );
            };

            // set the guid of unique handler to the same of original handler, so it can be removed
            proxy.guid = fn.guid = fn.guid || jquery.guid++;

            return proxy;
        },

        // multifunctional method to get and set values of a collection
        // the value/s can optionally be executed if it's a function
        access: function( elems, fn, key, value, chainable, emptyget, raw ) {
            var i = 0,
                length = elems.length,
                bulk = key == null;

            // sets many values
            if ( jquery.type( key ) === "object" ) {
                chainable = true;
                for ( i in key ) {
                    jquery.access( elems, fn, i, key[i], true, emptyget, raw );
                }

                // sets one value
            } else if ( value !== undefined ) {
                chainable = true;

                if ( !jquery.isfunction( value ) ) {
                    raw = true;
                }

                if ( bulk ) {
                    // bulk operations run against the entire set
                    if ( raw ) {
                        fn.call( elems, value );
                        fn = null;

                        // ...except when executing function values
                    } else {
                        bulk = fn;
                        fn = function( elem, key, value ) {
                            return bulk.call( jquery( elem ), value );
                        };
                    }
                }

                if ( fn ) {
                    for ( ; i < length; i++ ) {
                        fn( elems[i], key, raw ? value : value.call( elems[i], i, fn( elems[i], key ) ) );
                    }
                }
            }

            return chainable ?
                elems :

                // gets
                bulk ?
                    fn.call( elems ) :
                    length ? fn( elems[0], key ) : emptyget;
        },

        now: function() {
            return ( new date() ).gettime();
        },

        // a method for quickly swapping in/out css properties to get correct calculations.
        // note: this method belongs to the css module but it's needed here for the support module.
        // if support gets modularized, this method should be moved back to the css module.
        swap: function( elem, options, callback, args ) {
            var ret, name,
                old = {};

            // remember the old values, and insert the new ones
            for ( name in options ) {
                old[ name ] = elem.style[ name ];
                elem.style[ name ] = options[ name ];
            }

            ret = callback.apply( elem, args || [] );

            // revert the old values
            for ( name in options ) {
                elem.style[ name ] = old[ name ];
            }

            return ret;
        }
    });

    jquery.ready.promise = function( obj ) {
        if ( !readylist ) {

            readylist = jquery.deferred();

            // catch cases where $(document).ready() is called after the browser event has already occurred.
            // we once tried to use readystate "interactive" here, but it caused issues like the one
            // discovered by chriss here: http://bugs.jquery.com/ticket/12282#comment:15
            if ( document.readystate === "complete" ) {
                // handle it asynchronously to allow scripts the opportunity to delay ready
                settimeout( jquery.ready );

                // standards-based browsers support domcontentloaded
            } else if ( document.addeventlistener ) {
                // use the handy event callback
                document.addeventlistener( "domcontentloaded", completed, false );

                // a fallback to window.onload, that will always work
                window.addeventlistener( "load", completed, false );

                // if ie event model is used
            } else {
                // ensure firing before onload, maybe late but safe also for iframes
                document.attachevent( "onreadystatechange", completed );

                // a fallback to window.onload, that will always work
                window.attachevent( "onload", completed );

                // if ie and not a frame
                // continually check to see if the document is ready
                var top = false;

                try {
                    top = window.frameelement == null && document.documentelement;
                } catch(e) {}

                if ( top && top.doscroll ) {
                    (function doscrollcheck() {
                        if ( !jquery.isready ) {

                            try {
                                // use the trick by diego perini
                                // http://javascript.nwbox.com/iecontentloaded/
                                top.doscroll("left");
                            } catch(e) {
                                return settimeout( doscrollcheck, 50 );
                            }

                            // detach all dom ready events
                            detach();

                            // and execute any waiting functions
                            jquery.ready();
                        }
                    })();
                }
            }
        }
        return readylist.promise( obj );
    };

// populate the class2type map
    jquery.each("boolean number string function array date regexp object error".split(" "), function(i, name) {
        class2type[ "[object " + name + "]" ] = name.tolowercase();
    });

    function isarraylike( obj ) {
        var length = obj.length,
            type = jquery.type( obj );

        if ( jquery.iswindow( obj ) ) {
            return false;
        }

        if ( obj.nodetype === 1 && length ) {
            return true;
        }

        return type === "array" || type !== "function" &&
            ( length === 0 ||
                typeof length === "number" && length > 0 && ( length - 1 ) in obj );
    }

// all jquery objects should point back to these
    rootjquery = jquery(document);
    /*!
     * sizzle css selector engine v1.10.2
     * http://sizzlejs.com/
     *
     * copyright 2013 jquery foundation, inc. and other contributors
     * released under the mit license
     * http://jquery.org/license
     *
     * date: 2013-07-03
     */
    (function( window, undefined ) {

        var i,
            support,
            cachedruns,
            expr,
            gettext,
            isxml,
            compile,
            outermostcontext,
            sortinput,

        // local document vars
            setdocument,
            document,
            docelem,
            documentishtml,
            rbuggyqsa,
            rbuggymatches,
            matches,
            contains,

        // instance-specific data
            expando = "sizzle" + -(new date()),
            preferreddoc = window.document,
            dirruns = 0,
            done = 0,
            classcache = createcache(),
            tokencache = createcache(),
            compilercache = createcache(),
            hasduplicate = false,
            sortorder = function( a, b ) {
                if ( a === b ) {
                    hasduplicate = true;
                    return 0;
                }
                return 0;
            },

        // general-purpose constants
            strundefined = typeof undefined,
            max_negative = 1 << 31,

        // instance methods
            hasown = ({}).hasownproperty,
            arr = [],
            pop = arr.pop,
            push_native = arr.push,
            push = arr.push,
            slice = arr.slice,
        // use a stripped-down indexof if we can't use a native one
            indexof = arr.indexof || function( elem ) {
                var i = 0,
                    len = this.length;
                for ( ; i < len; i++ ) {
                    if ( this[i] === elem ) {
                        return i;
                    }
                }
                return -1;
            },

            booleans = "checked|selected|async|autofocus|autoplay|controls|defer|disabled|hidden|ismap|loop|multiple|open|readonly|required|scoped",

        // regular expressions

        // whitespace characters http://www.w3.org/tr/css3-selectors/#whitespace
            whitespace = "[\\x20\\t\\r\\n\\f]",
        // http://www.w3.org/tr/css3-syntax/#characters
            characterencoding = "(?:\\\\.|[\\w-]|[^\\x00-\\xa0])+",

        // loosely modeled on css identifier characters
        // an unquoted value should be a css identifier http://www.w3.org/tr/css3-selectors/#attribute-selectors
        // proper syntax: http://www.w3.org/tr/css21/syndata.html#value-def-identifier
            identifier = characterencoding.replace( "w", "w#" ),

        // acceptable operators http://www.w3.org/tr/selectors/#attribute-selectors
            attributes = "\\[" + whitespace + "*(" + characterencoding + ")" + whitespace +
                "*(?:([*^$|!~]?=)" + whitespace + "*(?:(['\"])((?:\\\\.|[^\\\\])*?)\\3|(" + identifier + ")|)|)" + whitespace + "*\\]",

        // prefer arguments quoted,
        //   then not containing pseudos/brackets,
        //   then attribute selectors/non-parenthetical expressions,
        //   then anything else
        // these preferences are here to reduce the number of selectors
        //   needing tokenize in the pseudo prefilter
            pseudos = ":(" + characterencoding + ")(?:\\(((['\"])((?:\\\\.|[^\\\\])*?)\\3|((?:\\\\.|[^\\\\()[\\]]|" + attributes.replace( 3, 8 ) + ")*)|.*)\\)|)",

        // leading and non-escaped trailing whitespace, capturing some non-whitespace characters preceding the latter
            rtrim = new regexp( "^" + whitespace + "+|((?:^|[^\\\\])(?:\\\\.)*)" + whitespace + "+$", "g" ),

            rcomma = new regexp( "^" + whitespace + "*," + whitespace + "*" ),
            rcombinators = new regexp( "^" + whitespace + "*([>+~]|" + whitespace + ")" + whitespace + "*" ),

            rsibling = new regexp( whitespace + "*[+~]" ),
            rattributequotes = new regexp( "=" + whitespace + "*([^\\]'\"]*)" + whitespace + "*\\]", "g" ),

            rpseudo = new regexp( pseudos ),
            ridentifier = new regexp( "^" + identifier + "$" ),

            matchexpr = {
                "id": new regexp( "^#(" + characterencoding + ")" ),
                "class": new regexp( "^\\.(" + characterencoding + ")" ),
                "tag": new regexp( "^(" + characterencoding.replace( "w", "w*" ) + ")" ),
                "attr": new regexp( "^" + attributes ),
                "pseudo": new regexp( "^" + pseudos ),
                "child": new regexp( "^:(only|first|last|nth|nth-last)-(child|of-type)(?:\\(" + whitespace +
                    "*(even|odd|(([+-]|)(\\d*)n|)" + whitespace + "*(?:([+-]|)" + whitespace +
                    "*(\\d+)|))" + whitespace + "*\\)|)", "i" ),
                "bool": new regexp( "^(?:" + booleans + ")$", "i" ),
                // for use in libraries implementing .is()
                // we use this for pos matching in `select`
                "needscontext": new regexp( "^" + whitespace + "*[>+~]|:(even|odd|eq|gt|lt|nth|first|last)(?:\\(" +
                    whitespace + "*((?:-\\d)?\\d*)" + whitespace + "*\\)|)(?=[^-]|$)", "i" )
            },

            rnative = /^[^{]+\{\s*\[native \w/,

        // easily-parseable/retrievable id or tag or class selectors
            rquickexpr = /^(?:#([\w-]+)|(\w+)|\.([\w-]+))$/,

            rinputs = /^(?:input|select|textarea|button)$/i,
            rheader = /^h\d$/i,

            rescape = /'|\\/g,

        // css escapes http://www.w3.org/tr/css21/syndata.html#escaped-characters
            runescape = new regexp( "\\\\([\\da-f]{1,6}" + whitespace + "?|(" + whitespace + ")|.)", "ig" ),
            funescape = function( _, escaped, escapedwhitespace ) {
                var high = "0x" + escaped - 0x10000;
                // nan means non-codepoint
                // support: firefox
                // workaround erroneous numeric interpretation of +"0x"
                return high !== high || escapedwhitespace ?
                    escaped :
                    // bmp codepoint
                        high < 0 ?
                    string.fromcharcode( high + 0x10000 ) :
                    // supplemental plane codepoint (surrogate pair)
                    string.fromcharcode( high >> 10 | 0xd800, high & 0x3ff | 0xdc00 );
            };

// optimize for push.apply( _, nodelist )
        try {
            push.apply(
                (arr = slice.call( preferreddoc.childnodes )),
                preferreddoc.childnodes
            );
            // support: android<4.0
            // detect silently failing push.apply
            arr[ preferreddoc.childnodes.length ].nodetype;
        } catch ( e ) {
            push = { apply: arr.length ?

                // leverage slice if possible
                function( target, els ) {
                    push_native.apply( target, slice.call(els) );
                } :

                // support: ie<9
                // otherwise append directly
                function( target, els ) {
                    var j = target.length,
                        i = 0;
                    // can't trust nodelist.length
                    while ( (target[j++] = els[i++]) ) {}
                    target.length = j - 1;
                }
            };
        }

        function sizzle( selector, context, results, seed ) {
            var match, elem, m, nodetype,
            // qsa vars
                i, groups, old, nid, newcontext, newselector;

            if ( ( context ? context.ownerdocument || context : preferreddoc ) !== document ) {
                setdocument( context );
            }

            context = context || document;
            results = results || [];

            if ( !selector || typeof selector !== "string" ) {
                return results;
            }

            if ( (nodetype = context.nodetype) !== 1 && nodetype !== 9 ) {
                return [];
            }

            if ( documentishtml && !seed ) {

                // shortcuts
                if ( (match = rquickexpr.exec( selector )) ) {
                    // speed-up: sizzle("#id")
                    if ( (m = match[1]) ) {
                        if ( nodetype === 9 ) {
                            elem = context.getelementbyid( m );
                            // check parentnode to catch when blackberry 4.6 returns
                            // nodes that are no longer in the document #6963
                            if ( elem && elem.parentnode ) {
                                // handle the case where ie, opera, and webkit return items
                                // by name instead of id
                                if ( elem.id === m ) {
                                    results.push( elem );
                                    return results;
                                }
                            } else {
                                return results;
                            }
                        } else {
                            // context is not a document
                            if ( context.ownerdocument && (elem = context.ownerdocument.getelementbyid( m )) &&
                                contains( context, elem ) && elem.id === m ) {
                                results.push( elem );
                                return results;
                            }
                        }

                        // speed-up: sizzle("tag")
                    } else if ( match[2] ) {
                        push.apply( results, context.getelementsbytagname( selector ) );
                        return results;

                        // speed-up: sizzle(".class")
                    } else if ( (m = match[3]) && support.getelementsbyclassname && context.getelementsbyclassname ) {
                        push.apply( results, context.getelementsbyclassname( m ) );
                        return results;
                    }
                }

                // qsa path
                if ( support.qsa && (!rbuggyqsa || !rbuggyqsa.test( selector )) ) {
                    nid = old = expando;
                    newcontext = context;
                    newselector = nodetype === 9 && selector;

                    // qsa works strangely on element-rooted queries
                    // we can work around this by specifying an extra id on the root
                    // and working up from there (thanks to andrew dupont for the technique)
                    // ie 8 doesn't work on object elements
                    if ( nodetype === 1 && context.nodename.tolowercase() !== "object" ) {
                        groups = tokenize( selector );

                        if ( (old = context.getattribute("id")) ) {
                            nid = old.replace( rescape, "\\$&" );
                        } else {
                            context.setattribute( "id", nid );
                        }
                        nid = "[id='" + nid + "'] ";

                        i = groups.length;
                        while ( i-- ) {
                            groups[i] = nid + toselector( groups[i] );
                        }
                        newcontext = rsibling.test( selector ) && context.parentnode || context;
                        newselector = groups.join(",");
                    }

                    if ( newselector ) {
                        try {
                            push.apply( results,
                                newcontext.queryselectorall( newselector )
                            );
                            return results;
                        } catch(qsaerror) {
                        } finally {
                            if ( !old ) {
                                context.removeattribute("id");
                            }
                        }
                    }
                }
            }

            // all others
            return select( selector.replace( rtrim, "$1" ), context, results, seed );
        }

        /**
         * create key-value caches of limited size
         * @returns {function(string, object)} returns the object data after storing it on itself with
         *	property name the (space-suffixed) string and (if the cache is larger than expr.cachelength)
         *	deleting the oldest entry
         */
        function createcache() {
            var keys = [];

            function cache( key, value ) {
                // use (key + " ") to avoid collision with native prototype properties (see issue #157)
                if ( keys.push( key += " " ) > expr.cachelength ) {
                    // only keep the most recent entries
                    delete cache[ keys.shift() ];
                }
                return (cache[ key ] = value);
            }
            return cache;
        }

        /**
         * mark a function for special use by sizzle
         * @param {function} fn the function to mark
         */
        function markfunction( fn ) {
            fn[ expando ] = true;
            return fn;
        }

        /**
         * support testing using an element
         * @param {function} fn passed the created div and expects a boolean result
         */
        function assert( fn ) {
            var div = document.createelement("div");

            try {
                return !!fn( div );
            } catch (e) {
                return false;
            } finally {
                // remove from its parent by default
                if ( div.parentnode ) {
                    div.parentnode.removechild( div );
                }
                // release memory in ie
                div = null;
            }
        }

        /**
         * adds the same handler for all of the specified attrs
         * @param {string} attrs pipe-separated list of attributes
         * @param {function} handler the method that will be applied
         */
        function addhandle( attrs, handler ) {
            var arr = attrs.split("|"),
                i = attrs.length;

            while ( i-- ) {
                expr.attrhandle[ arr[i] ] = handler;
            }
        }

        /**
         * checks document order of two siblings
         * @param {element} a
         * @param {element} b
         * @returns {number} returns less than 0 if a precedes b, greater than 0 if a follows b
         */
        function siblingcheck( a, b ) {
            var cur = b && a,
                diff = cur && a.nodetype === 1 && b.nodetype === 1 &&
                    ( ~b.sourceindex || max_negative ) -
                    ( ~a.sourceindex || max_negative );

            // use ie sourceindex if available on both nodes
            if ( diff ) {
                return diff;
            }

            // check if b follows a
            if ( cur ) {
                while ( (cur = cur.nextsibling) ) {
                    if ( cur === b ) {
                        return -1;
                    }
                }
            }

            return a ? 1 : -1;
        }

        /**
         * returns a function to use in pseudos for input types
         * @param {string} type
         */
        function createinputpseudo( type ) {
            return function( elem ) {
                var name = elem.nodename.tolowercase();
                return name === "input" && elem.type === type;
            };
        }

        /**
         * returns a function to use in pseudos for buttons
         * @param {string} type
         */
        function createbuttonpseudo( type ) {
            return function( elem ) {
                var name = elem.nodename.tolowercase();
                return (name === "input" || name === "button") && elem.type === type;
            };
        }

        /**
         * returns a function to use in pseudos for positionals
         * @param {function} fn
         */
        function createpositionalpseudo( fn ) {
            return markfunction(function( argument ) {
                argument = +argument;
                return markfunction(function( seed, matches ) {
                    var j,
                        matchindexes = fn( [], seed.length, argument ),
                        i = matchindexes.length;

                    // match elements found at the specified indexes
                    while ( i-- ) {
                        if ( seed[ (j = matchindexes[i]) ] ) {
                            seed[j] = !(matches[j] = seed[j]);
                        }
                    }
                });
            });
        }

        /**
         * detect xml
         * @param {element|object} elem an element or a document
         */
        isxml = sizzle.isxml = function( elem ) {
            // documentelement is verified for cases where it doesn't yet exist
            // (such as loading iframes in ie - #4833)
            var documentelement = elem && (elem.ownerdocument || elem).documentelement;
            return documentelement ? documentelement.nodename !== "html" : false;
        };

// expose support vars for convenience
        support = sizzle.support = {};

        /**
         * sets document-related variables once based on the current document
         * @param {element|object} [doc] an element or document object to use to set the document
         * @returns {object} returns the current document
         */
        setdocument = sizzle.setdocument = function( node ) {
            var doc = node ? node.ownerdocument || node : preferreddoc,
                parent = doc.defaultview;

            // if no document and documentelement is available, return
            if ( doc === document || doc.nodetype !== 9 || !doc.documentelement ) {
                return document;
            }

            // set our document
            document = doc;
            docelem = doc.documentelement;

            // support tests
            documentishtml = !isxml( doc );

            // support: ie>8
            // if iframe document is assigned to "document" variable and if iframe has been reloaded,
            // ie will throw "permission denied" error when accessing "document" variable, see jquery #13936
            // ie6-8 do not support the defaultview property so parent will be undefined
            if ( parent && parent.attachevent && parent !== parent.top ) {
                parent.attachevent( "onbeforeunload", function() {
                    setdocument();
                });
            }

            /* attributes
             ---------------------------------------------------------------------- */

            // support: ie<8
            // verify that getattribute really returns attributes and not properties (excepting ie8 booleans)
            support.attributes = assert(function( div ) {
                div.classname = "i";
                return !div.getattribute("classname");
            });

            /* getelement(s)by*
             ---------------------------------------------------------------------- */

            // check if getelementsbytagname("*") returns only elements
            support.getelementsbytagname = assert(function( div ) {
                div.appendchild( doc.createcomment("") );
                return !div.getelementsbytagname("*").length;
            });

            // check if getelementsbyclassname can be trusted
            support.getelementsbyclassname = assert(function( div ) {
                div.innerhtml = "<div class='a'></div><div class='a i'></div>";

                // support: safari<4
                // catch class over-caching
                div.firstchild.classname = "i";
                // support: opera<10
                // catch gebcn failure to find non-leading classes
                return div.getelementsbyclassname("i").length === 2;
            });

            // support: ie<10
            // check if getelementbyid returns elements by name
            // the broken getelementbyid methods don't pick up programatically-set names,
            // so use a roundabout getelementsbyname test
            support.getbyid = assert(function( div ) {
                docelem.appendchild( div ).id = expando;
                return !doc.getelementsbyname || !doc.getelementsbyname( expando ).length;
            });

            // id find and filter
            if ( support.getbyid ) {
                expr.find["id"] = function( id, context ) {
                    if ( typeof context.getelementbyid !== strundefined && documentishtml ) {
                        var m = context.getelementbyid( id );
                        // check parentnode to catch when blackberry 4.6 returns
                        // nodes that are no longer in the document #6963
                        return m && m.parentnode ? [m] : [];
                    }
                };
                expr.filter["id"] = function( id ) {
                    var attrid = id.replace( runescape, funescape );
                    return function( elem ) {
                        return elem.getattribute("id") === attrid;
                    };
                };
            } else {
                // support: ie6/7
                // getelementbyid is not reliable as a find shortcut
                delete expr.find["id"];

                expr.filter["id"] =  function( id ) {
                    var attrid = id.replace( runescape, funescape );
                    return function( elem ) {
                        var node = typeof elem.getattributenode !== strundefined && elem.getattributenode("id");
                        return node && node.value === attrid;
                    };
                };
            }

            // tag
            expr.find["tag"] = support.getelementsbytagname ?
                function( tag, context ) {
                    if ( typeof context.getelementsbytagname !== strundefined ) {
                        return context.getelementsbytagname( tag );
                    }
                } :
                function( tag, context ) {
                    var elem,
                        tmp = [],
                        i = 0,
                        results = context.getelementsbytagname( tag );

                    // filter out possible comments
                    if ( tag === "*" ) {
                        while ( (elem = results[i++]) ) {
                            if ( elem.nodetype === 1 ) {
                                tmp.push( elem );
                            }
                        }

                        return tmp;
                    }
                    return results;
                };

            // class
            expr.find["class"] = support.getelementsbyclassname && function( classname, context ) {
                if ( typeof context.getelementsbyclassname !== strundefined && documentishtml ) {
                    return context.getelementsbyclassname( classname );
                }
            };

            /* qsa/matchesselector
             ---------------------------------------------------------------------- */

            // qsa and matchesselector support

            // matchesselector(:active) reports false when true (ie9/opera 11.5)
            rbuggymatches = [];

            // qsa(:focus) reports false when true (chrome 21)
            // we allow this because of a bug in ie8/9 that throws an error
            // whenever `document.activeelement` is accessed on an iframe
            // so, we allow :focus to pass through qsa all the time to avoid the ie error
            // see http://bugs.jquery.com/ticket/13378
            rbuggyqsa = [];

            if ( (support.qsa = rnative.test( doc.queryselectorall )) ) {
                // build qsa regex
                // regex strategy adopted from diego perini
                assert(function( div ) {
                    // select is set to empty string on purpose
                    // this is to test ie's treatment of not explicitly
                    // setting a boolean content attribute,
                    // since its presence should be enough
                    // http://bugs.jquery.com/ticket/12359
                    div.innerhtml = "<select><option selected=''></option></select>";

                    // support: ie8
                    // boolean attributes and "value" are not treated correctly
                    if ( !div.queryselectorall("[selected]").length ) {
                        rbuggyqsa.push( "\\[" + whitespace + "*(?:value|" + booleans + ")" );
                    }

                    // webkit/opera - :checked should return selected option elements
                    // http://www.w3.org/tr/2011/rec-css3-selectors-20110929/#checked
                    // ie8 throws error here and will not see later tests
                    if ( !div.queryselectorall(":checked").length ) {
                        rbuggyqsa.push(":checked");
                    }
                });

                assert(function( div ) {

                    // support: opera 10-12/ie8
                    // ^= $= *= and empty values
                    // should not select anything
                    // support: windows 8 native apps
                    // the type attribute is restricted during .innerhtml assignment
                    var input = doc.createelement("input");
                    input.setattribute( "type", "hidden" );
                    div.appendchild( input ).setattribute( "t", "" );

                    if ( div.queryselectorall("[t^='']").length ) {
                        rbuggyqsa.push( "[*^$]=" + whitespace + "*(?:''|\"\")" );
                    }

                    // ff 3.5 - :enabled/:disabled and hidden elements (hidden elements are still enabled)
                    // ie8 throws error here and will not see later tests
                    if ( !div.queryselectorall(":enabled").length ) {
                        rbuggyqsa.push( ":enabled", ":disabled" );
                    }

                    // opera 10-11 does not throw on post-comma invalid pseudos
                    div.queryselectorall("*,:x");
                    rbuggyqsa.push(",.*:");
                });
            }

            if ( (support.matchesselector = rnative.test( (matches = docelem.webkitmatchesselector ||
                docelem.mozmatchesselector ||
                docelem.omatchesselector ||
                docelem.msmatchesselector) )) ) {

                assert(function( div ) {
                    // check to see if it's possible to do matchesselector
                    // on a disconnected node (ie 9)
                    support.disconnectedmatch = matches.call( div, "div" );

                    // this should fail with an exception
                    // gecko does not error, returns false instead
                    matches.call( div, "[s!='']:x" );
                    rbuggymatches.push( "!=", pseudos );
                });
            }

            rbuggyqsa = rbuggyqsa.length && new regexp( rbuggyqsa.join("|") );
            rbuggymatches = rbuggymatches.length && new regexp( rbuggymatches.join("|") );

            /* contains
             ---------------------------------------------------------------------- */

            // element contains another
            // purposefully does not implement inclusive descendent
            // as in, an element does not contain itself
            contains = rnative.test( docelem.contains ) || docelem.comparedocumentposition ?
                function( a, b ) {
                    var adown = a.nodetype === 9 ? a.documentelement : a,
                        bup = b && b.parentnode;
                    return a === bup || !!( bup && bup.nodetype === 1 && (
                        adown.contains ?
                            adown.contains( bup ) :
                            a.comparedocumentposition && a.comparedocumentposition( bup ) & 16
                        ));
                } :
                function( a, b ) {
                    if ( b ) {
                        while ( (b = b.parentnode) ) {
                            if ( b === a ) {
                                return true;
                            }
                        }
                    }
                    return false;
                };

            /* sorting
             ---------------------------------------------------------------------- */

            // document order sorting
            sortorder = docelem.comparedocumentposition ?
                function( a, b ) {

                    // flag for duplicate removal
                    if ( a === b ) {
                        hasduplicate = true;
                        return 0;
                    }

                    var compare = b.comparedocumentposition && a.comparedocumentposition && a.comparedocumentposition( b );

                    if ( compare ) {
                        // disconnected nodes
                        if ( compare & 1 ||
                            (!support.sortdetached && b.comparedocumentposition( a ) === compare) ) {

                            // choose the first element that is related to our preferred document
                            if ( a === doc || contains(preferreddoc, a) ) {
                                return -1;
                            }
                            if ( b === doc || contains(preferreddoc, b) ) {
                                return 1;
                            }

                            // maintain original order
                            return sortinput ?
                                ( indexof.call( sortinput, a ) - indexof.call( sortinput, b ) ) :
                                0;
                        }

                        return compare & 4 ? -1 : 1;
                    }

                    // not directly comparable, sort on existence of method
                    return a.comparedocumentposition ? -1 : 1;
                } :
                function( a, b ) {
                    var cur,
                        i = 0,
                        aup = a.parentnode,
                        bup = b.parentnode,
                        ap = [ a ],
                        bp = [ b ];

                    // exit early if the nodes are identical
                    if ( a === b ) {
                        hasduplicate = true;
                        return 0;

                        // parentless nodes are either documents or disconnected
                    } else if ( !aup || !bup ) {
                        return a === doc ? -1 :
                                b === doc ? 1 :
                            aup ? -1 :
                                bup ? 1 :
                                    sortinput ?
                                        ( indexof.call( sortinput, a ) - indexof.call( sortinput, b ) ) :
                                        0;

                        // if the nodes are siblings, we can do a quick check
                    } else if ( aup === bup ) {
                        return siblingcheck( a, b );
                    }

                    // otherwise we need full lists of their ancestors for comparison
                    cur = a;
                    while ( (cur = cur.parentnode) ) {
                        ap.unshift( cur );
                    }
                    cur = b;
                    while ( (cur = cur.parentnode) ) {
                        bp.unshift( cur );
                    }

                    // walk down the tree looking for a discrepancy
                    while ( ap[i] === bp[i] ) {
                        i++;
                    }

                    return i ?
                        // do a sibling check if the nodes have a common ancestor
                        siblingcheck( ap[i], bp[i] ) :

                        // otherwise nodes in our document sort first
                            ap[i] === preferreddoc ? -1 :
                            bp[i] === preferreddoc ? 1 :
                        0;
                };

            return doc;
        };

        sizzle.matches = function( expr, elements ) {
            return sizzle( expr, null, null, elements );
        };

        sizzle.matchesselector = function( elem, expr ) {
            // set document vars if needed
            if ( ( elem.ownerdocument || elem ) !== document ) {
                setdocument( elem );
            }

            // make sure that attribute selectors are quoted
            expr = expr.replace( rattributequotes, "='$1']" );

            if ( support.matchesselector && documentishtml &&
                ( !rbuggymatches || !rbuggymatches.test( expr ) ) &&
                ( !rbuggyqsa     || !rbuggyqsa.test( expr ) ) ) {

                try {
                    var ret = matches.call( elem, expr );

                    // ie 9's matchesselector returns false on disconnected nodes
                    if ( ret || support.disconnectedmatch ||
                        // as well, disconnected nodes are said to be in a document
                        // fragment in ie 9
                        elem.document && elem.document.nodetype !== 11 ) {
                        return ret;
                    }
                } catch(e) {}
            }

            return sizzle( expr, document, null, [elem] ).length > 0;
        };

        sizzle.contains = function( context, elem ) {
            // set document vars if needed
            if ( ( context.ownerdocument || context ) !== document ) {
                setdocument( context );
            }
            return contains( context, elem );
        };

        sizzle.attr = function( elem, name ) {
            // set document vars if needed
            if ( ( elem.ownerdocument || elem ) !== document ) {
                setdocument( elem );
            }

            var fn = expr.attrhandle[ name.tolowercase() ],
            // don't get fooled by object.prototype properties (jquery #13807)
                val = fn && hasown.call( expr.attrhandle, name.tolowercase() ) ?
                    fn( elem, name, !documentishtml ) :
                    undefined;

            return val === undefined ?
                    support.attributes || !documentishtml ?
                elem.getattribute( name ) :
                    (val = elem.getattributenode(name)) && val.specified ?
                val.value :
                null :
                val;
        };

        sizzle.error = function( msg ) {
            throw new error( "syntax error, unrecognized expression: " + msg );
        };

        /**
         * document sorting and removing duplicates
         * @param {arraylike} results
         */
        sizzle.uniquesort = function( results ) {
            var elem,
                duplicates = [],
                j = 0,
                i = 0;

            // unless we *know* we can detect duplicates, assume their presence
            hasduplicate = !support.detectduplicates;
            sortinput = !support.sortstable && results.slice( 0 );
            results.sort( sortorder );

            if ( hasduplicate ) {
                while ( (elem = results[i++]) ) {
                    if ( elem === results[ i ] ) {
                        j = duplicates.push( i );
                    }
                }
                while ( j-- ) {
                    results.splice( duplicates[ j ], 1 );
                }
            }

            return results;
        };

        /**
         * utility function for retrieving the text value of an array of dom nodes
         * @param {array|element} elem
         */
        gettext = sizzle.gettext = function( elem ) {
            var node,
                ret = "",
                i = 0,
                nodetype = elem.nodetype;

            if ( !nodetype ) {
                // if no nodetype, this is expected to be an array
                for ( ; (node = elem[i]); i++ ) {
                    // do not traverse comment nodes
                    ret += gettext( node );
                }
            } else if ( nodetype === 1 || nodetype === 9 || nodetype === 11 ) {
                // use textcontent for elements
                // innertext usage removed for consistency of new lines (see #11153)
                if ( typeof elem.textcontent === "string" ) {
                    return elem.textcontent;
                } else {
                    // traverse its children
                    for ( elem = elem.firstchild; elem; elem = elem.nextsibling ) {
                        ret += gettext( elem );
                    }
                }
            } else if ( nodetype === 3 || nodetype === 4 ) {
                return elem.nodevalue;
            }
            // do not include comment or processing instruction nodes

            return ret;
        };

        expr = sizzle.selectors = {

            // can be adjusted by the user
            cachelength: 50,

            createpseudo: markfunction,

            match: matchexpr,

            attrhandle: {},

            find: {},

            relative: {
                ">": { dir: "parentnode", first: true },
                " ": { dir: "parentnode" },
                "+": { dir: "previoussibling", first: true },
                "~": { dir: "previoussibling" }
            },

            prefilter: {
                "attr": function( match ) {
                    match[1] = match[1].replace( runescape, funescape );

                    // move the given value to match[3] whether quoted or unquoted
                    match[3] = ( match[4] || match[5] || "" ).replace( runescape, funescape );

                    if ( match[2] === "~=" ) {
                        match[3] = " " + match[3] + " ";
                    }

                    return match.slice( 0, 4 );
                },

                "child": function( match ) {
                    /* matches from matchexpr["child"]
                     1 type (only|nth|...)
                     2 what (child|of-type)
                     3 argument (even|odd|\d*|\d*n([+-]\d+)?|...)
                     4 xn-component of xn+y argument ([+-]?\d*n|)
                     5 sign of xn-component
                     6 x of xn-component
                     7 sign of y-component
                     8 y of y-component
                     */
                    match[1] = match[1].tolowercase();

                    if ( match[1].slice( 0, 3 ) === "nth" ) {
                        // nth-* requires argument
                        if ( !match[3] ) {
                            sizzle.error( match[0] );
                        }

                        // numeric x and y parameters for expr.filter.child
                        // remember that false/true cast respectively to 0/1
                        match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === "even" || match[3] === "odd" ) );
                        match[5] = +( ( match[7] + match[8] ) || match[3] === "odd" );

                        // other types prohibit arguments
                    } else if ( match[3] ) {
                        sizzle.error( match[0] );
                    }

                    return match;
                },

                "pseudo": function( match ) {
                    var excess,
                        unquoted = !match[5] && match[2];

                    if ( matchexpr["child"].test( match[0] ) ) {
                        return null;
                    }

                    // accept quoted arguments as-is
                    if ( match[3] && match[4] !== undefined ) {
                        match[2] = match[4];

                        // strip excess characters from unquoted arguments
                    } else if ( unquoted && rpseudo.test( unquoted ) &&
                        // get excess from tokenize (recursively)
                        (excess = tokenize( unquoted, true )) &&
                        // advance to the next closing parenthesis
                        (excess = unquoted.indexof( ")", unquoted.length - excess ) - unquoted.length) ) {

                        // excess is a negative index
                        match[0] = match[0].slice( 0, excess );
                        match[2] = unquoted.slice( 0, excess );
                    }

                    // return only captures needed by the pseudo filter method (type and argument)
                    return match.slice( 0, 3 );
                }
            },

            filter: {

                "tag": function( nodenameselector ) {
                    var nodename = nodenameselector.replace( runescape, funescape ).tolowercase();
                    return nodenameselector === "*" ?
                        function() { return true; } :
                        function( elem ) {
                            return elem.nodename && elem.nodename.tolowercase() === nodename;
                        };
                },

                "class": function( classname ) {
                    var pattern = classcache[ classname + " " ];

                    return pattern ||
                        (pattern = new regexp( "(^|" + whitespace + ")" + classname + "(" + whitespace + "|$)" )) &&
                        classcache( classname, function( elem ) {
                            return pattern.test( typeof elem.classname === "string" && elem.classname || typeof elem.getattribute !== strundefined && elem.getattribute("class") || "" );
                        });
                },

                "attr": function( name, operator, check ) {
                    return function( elem ) {
                        var result = sizzle.attr( elem, name );

                        if ( result == null ) {
                            return operator === "!=";
                        }
                        if ( !operator ) {
                            return true;
                        }

                        result += "";

                        return operator === "=" ? result === check :
                                operator === "!=" ? result !== check :
                                operator === "^=" ? check && result.indexof( check ) === 0 :
                                operator === "*=" ? check && result.indexof( check ) > -1 :
                                operator === "$=" ? check && result.slice( -check.length ) === check :
                                operator === "~=" ? ( " " + result + " " ).indexof( check ) > -1 :
                                operator === "|=" ? result === check || result.slice( 0, check.length + 1 ) === check + "-" :
                            false;
                    };
                },

                "child": function( type, what, argument, first, last ) {
                    var simple = type.slice( 0, 3 ) !== "nth",
                        forward = type.slice( -4 ) !== "last",
                        oftype = what === "of-type";

                    return first === 1 && last === 0 ?

                        // shortcut for :nth-*(n)
                        function( elem ) {
                            return !!elem.parentnode;
                        } :

                        function( elem, context, xml ) {
                            var cache, outercache, node, diff, nodeindex, start,
                                dir = simple !== forward ? "nextsibling" : "previoussibling",
                                parent = elem.parentnode,
                                name = oftype && elem.nodename.tolowercase(),
                                usecache = !xml && !oftype;

                            if ( parent ) {

                                // :(first|last|only)-(child|of-type)
                                if ( simple ) {
                                    while ( dir ) {
                                        node = elem;
                                        while ( (node = node[ dir ]) ) {
                                            if ( oftype ? node.nodename.tolowercase() === name : node.nodetype === 1 ) {
                                                return false;
                                            }
                                        }
                                        // reverse direction for :only-* (if we haven't yet done so)
                                        start = dir = type === "only" && !start && "nextsibling";
                                    }
                                    return true;
                                }

                                start = [ forward ? parent.firstchild : parent.lastchild ];

                                // non-xml :nth-child(...) stores cache data on `parent`
                                if ( forward && usecache ) {
                                    // seek `elem` from a previously-cached index
                                    outercache = parent[ expando ] || (parent[ expando ] = {});
                                    cache = outercache[ type ] || [];
                                    nodeindex = cache[0] === dirruns && cache[1];
                                    diff = cache[0] === dirruns && cache[2];
                                    node = nodeindex && parent.childnodes[ nodeindex ];

                                    while ( (node = ++nodeindex && node && node[ dir ] ||

                                        // fallback to seeking `elem` from the start
                                        (diff = nodeindex = 0) || start.pop()) ) {

                                        // when found, cache indexes on `parent` and break
                                        if ( node.nodetype === 1 && ++diff && node === elem ) {
                                            outercache[ type ] = [ dirruns, nodeindex, diff ];
                                            break;
                                        }
                                    }

                                    // use previously-cached element index if available
                                } else if ( usecache && (cache = (elem[ expando ] || (elem[ expando ] = {}))[ type ]) && cache[0] === dirruns ) {
                                    diff = cache[1];

                                    // xml :nth-child(...) or :nth-last-child(...) or :nth(-last)?-of-type(...)
                                } else {
                                    // use the same loop as above to seek `elem` from the start
                                    while ( (node = ++nodeindex && node && node[ dir ] ||
                                        (diff = nodeindex = 0) || start.pop()) ) {

                                        if ( ( oftype ? node.nodename.tolowercase() === name : node.nodetype === 1 ) && ++diff ) {
                                            // cache the index of each encountered element
                                            if ( usecache ) {
                                                (node[ expando ] || (node[ expando ] = {}))[ type ] = [ dirruns, diff ];
                                            }

                                            if ( node === elem ) {
                                                break;
                                            }
                                        }
                                    }
                                }

                                // incorporate the offset, then check against cycle size
                                diff -= last;
                                return diff === first || ( diff % first === 0 && diff / first >= 0 );
                            }
                        };
                },

                "pseudo": function( pseudo, argument ) {
                    // pseudo-class names are case-insensitive
                    // http://www.w3.org/tr/selectors/#pseudo-classes
                    // prioritize by case sensitivity in case custom pseudos are added with uppercase letters
                    // remember that setfilters inherits from pseudos
                    var args,
                        fn = expr.pseudos[ pseudo ] || expr.setfilters[ pseudo.tolowercase() ] ||
                            sizzle.error( "unsupported pseudo: " + pseudo );

                    // the user may use createpseudo to indicate that
                    // arguments are needed to create the filter function
                    // just as sizzle does
                    if ( fn[ expando ] ) {
                        return fn( argument );
                    }

                    // but maintain support for old signatures
                    if ( fn.length > 1 ) {
                        args = [ pseudo, pseudo, "", argument ];
                        return expr.setfilters.hasownproperty( pseudo.tolowercase() ) ?
                            markfunction(function( seed, matches ) {
                                var idx,
                                    matched = fn( seed, argument ),
                                    i = matched.length;
                                while ( i-- ) {
                                    idx = indexof.call( seed, matched[i] );
                                    seed[ idx ] = !( matches[ idx ] = matched[i] );
                                }
                            }) :
                            function( elem ) {
                                return fn( elem, 0, args );
                            };
                    }

                    return fn;
                }
            },

            pseudos: {
                // potentially complex pseudos
                "not": markfunction(function( selector ) {
                    // trim the selector passed to compile
                    // to avoid treating leading and trailing
                    // spaces as combinators
                    var input = [],
                        results = [],
                        matcher = compile( selector.replace( rtrim, "$1" ) );

                    return matcher[ expando ] ?
                        markfunction(function( seed, matches, context, xml ) {
                            var elem,
                                unmatched = matcher( seed, null, xml, [] ),
                                i = seed.length;

                            // match elements unmatched by `matcher`
                            while ( i-- ) {
                                if ( (elem = unmatched[i]) ) {
                                    seed[i] = !(matches[i] = elem);
                                }
                            }
                        }) :
                        function( elem, context, xml ) {
                            input[0] = elem;
                            matcher( input, null, xml, results );
                            return !results.pop();
                        };
                }),

                "has": markfunction(function( selector ) {
                    return function( elem ) {
                        return sizzle( selector, elem ).length > 0;
                    };
                }),

                "contains": markfunction(function( text ) {
                    return function( elem ) {
                        return ( elem.textcontent || elem.innertext || gettext( elem ) ).indexof( text ) > -1;
                    };
                }),

                // "whether an element is represented by a :lang() selector
                // is based solely on the element's language value
                // being equal to the identifier c,
                // or beginning with the identifier c immediately followed by "-".
                // the matching of c against the element's language value is performed case-insensitively.
                // the identifier c does not have to be a valid language name."
                // http://www.w3.org/tr/selectors/#lang-pseudo
                "lang": markfunction( function( lang ) {
                    // lang value must be a valid identifier
                    if ( !ridentifier.test(lang || "") ) {
                        sizzle.error( "unsupported lang: " + lang );
                    }
                    lang = lang.replace( runescape, funescape ).tolowercase();
                    return function( elem ) {
                        var elemlang;
                        do {
                            if ( (elemlang = documentishtml ?
                                elem.lang :
                                elem.getattribute("xml:lang") || elem.getattribute("lang")) ) {

                                elemlang = elemlang.tolowercase();
                                return elemlang === lang || elemlang.indexof( lang + "-" ) === 0;
                            }
                        } while ( (elem = elem.parentnode) && elem.nodetype === 1 );
                        return false;
                    };
                }),

                // miscellaneous
                "target": function( elem ) {
                    var hash = window.location && window.location.hash;
                    return hash && hash.slice( 1 ) === elem.id;
                },

                "root": function( elem ) {
                    return elem === docelem;
                },

                "focus": function( elem ) {
                    return elem === document.activeelement && (!document.hasfocus || document.hasfocus()) && !!(elem.type || elem.href || ~elem.tabindex);
                },

                // boolean properties
                "enabled": function( elem ) {
                    return elem.disabled === false;
                },

                "disabled": function( elem ) {
                    return elem.disabled === true;
                },

                "checked": function( elem ) {
                    // in css3, :checked should return both checked and selected elements
                    // http://www.w3.org/tr/2011/rec-css3-selectors-20110929/#checked
                    var nodename = elem.nodename.tolowercase();
                    return (nodename === "input" && !!elem.checked) || (nodename === "option" && !!elem.selected);
                },

                "selected": function( elem ) {
                    // accessing this property makes selected-by-default
                    // options in safari work properly
                    if ( elem.parentnode ) {
                        elem.parentnode.selectedindex;
                    }

                    return elem.selected === true;
                },

                // contents
                "empty": function( elem ) {
                    // http://www.w3.org/tr/selectors/#empty-pseudo
                    // :empty is only affected by element nodes and content nodes(including text(3), cdata(4)),
                    //   not comment, processing instructions, or others
                    // thanks to diego perini for the nodename shortcut
                    //   greater than "@" means alpha characters (specifically not starting with "#" or "?")
                    for ( elem = elem.firstchild; elem; elem = elem.nextsibling ) {
                        if ( elem.nodename > "@" || elem.nodetype === 3 || elem.nodetype === 4 ) {
                            return false;
                        }
                    }
                    return true;
                },

                "parent": function( elem ) {
                    return !expr.pseudos["empty"]( elem );
                },

                // element/input types
                "header": function( elem ) {
                    return rheader.test( elem.nodename );
                },

                "input": function( elem ) {
                    return rinputs.test( elem.nodename );
                },

                "button": function( elem ) {
                    var name = elem.nodename.tolowercase();
                    return name === "input" && elem.type === "button" || name === "button";
                },

                "text": function( elem ) {
                    var attr;
                    // ie6 and 7 will map elem.type to 'text' for new html5 types (search, etc)
                    // use getattribute instead to test this case
                    return elem.nodename.tolowercase() === "input" &&
                        elem.type === "text" &&
                        ( (attr = elem.getattribute("type")) == null || attr.tolowercase() === elem.type );
                },

                // position-in-collection
                "first": createpositionalpseudo(function() {
                    return [ 0 ];
                }),

                "last": createpositionalpseudo(function( matchindexes, length ) {
                    return [ length - 1 ];
                }),

                "eq": createpositionalpseudo(function( matchindexes, length, argument ) {
                    return [ argument < 0 ? argument + length : argument ];
                }),

                "even": createpositionalpseudo(function( matchindexes, length ) {
                    var i = 0;
                    for ( ; i < length; i += 2 ) {
                        matchindexes.push( i );
                    }
                    return matchindexes;
                }),

                "odd": createpositionalpseudo(function( matchindexes, length ) {
                    var i = 1;
                    for ( ; i < length; i += 2 ) {
                        matchindexes.push( i );
                    }
                    return matchindexes;
                }),

                "lt": createpositionalpseudo(function( matchindexes, length, argument ) {
                    var i = argument < 0 ? argument + length : argument;
                    for ( ; --i >= 0; ) {
                        matchindexes.push( i );
                    }
                    return matchindexes;
                }),

                "gt": createpositionalpseudo(function( matchindexes, length, argument ) {
                    var i = argument < 0 ? argument + length : argument;
                    for ( ; ++i < length; ) {
                        matchindexes.push( i );
                    }
                    return matchindexes;
                })
            }
        };

        expr.pseudos["nth"] = expr.pseudos["eq"];

// add button/input type pseudos
        for ( i in { radio: true, checkbox: true, file: true, password: true, image: true } ) {
            expr.pseudos[ i ] = createinputpseudo( i );
        }
        for ( i in { submit: true, reset: true } ) {
            expr.pseudos[ i ] = createbuttonpseudo( i );
        }

// easy api for creating new setfilters
        function setfilters() {}
        setfilters.prototype = expr.filters = expr.pseudos;
        expr.setfilters = new setfilters();

        function tokenize( selector, parseonly ) {
            var matched, match, tokens, type,
                sofar, groups, prefilters,
                cached = tokencache[ selector + " " ];

            if ( cached ) {
                return parseonly ? 0 : cached.slice( 0 );
            }

            sofar = selector;
            groups = [];
            prefilters = expr.prefilter;

            while ( sofar ) {

                // comma and first run
                if ( !matched || (match = rcomma.exec( sofar )) ) {
                    if ( match ) {
                        // don't consume trailing commas as valid
                        sofar = sofar.slice( match[0].length ) || sofar;
                    }
                    groups.push( tokens = [] );
                }

                matched = false;

                // combinators
                if ( (match = rcombinators.exec( sofar )) ) {
                    matched = match.shift();
                    tokens.push({
                        value: matched,
                        // cast descendant combinators to space
                        type: match[0].replace( rtrim, " " )
                    });
                    sofar = sofar.slice( matched.length );
                }

                // filters
                for ( type in expr.filter ) {
                    if ( (match = matchexpr[ type ].exec( sofar )) && (!prefilters[ type ] ||
                        (match = prefilters[ type ]( match ))) ) {
                        matched = match.shift();
                        tokens.push({
                            value: matched,
                            type: type,
                            matches: match
                        });
                        sofar = sofar.slice( matched.length );
                    }
                }

                if ( !matched ) {
                    break;
                }
            }

            // return the length of the invalid excess
            // if we're just parsing
            // otherwise, throw an error or return tokens
            return parseonly ?
                sofar.length :
                sofar ?
                    sizzle.error( selector ) :
                    // cache the tokens
                    tokencache( selector, groups ).slice( 0 );
        }

        function toselector( tokens ) {
            var i = 0,
                len = tokens.length,
                selector = "";
            for ( ; i < len; i++ ) {
                selector += tokens[i].value;
            }
            return selector;
        }

        function addcombinator( matcher, combinator, base ) {
            var dir = combinator.dir,
                checknonelements = base && dir === "parentnode",
                donename = done++;

            return combinator.first ?
                // check against closest ancestor/preceding element
                function( elem, context, xml ) {
                    while ( (elem = elem[ dir ]) ) {
                        if ( elem.nodetype === 1 || checknonelements ) {
                            return matcher( elem, context, xml );
                        }
                    }
                } :

                // check against all ancestor/preceding elements
                function( elem, context, xml ) {
                    var data, cache, outercache,
                        dirkey = dirruns + " " + donename;

                    // we can't set arbitrary data on xml nodes, so they don't benefit from dir caching
                    if ( xml ) {
                        while ( (elem = elem[ dir ]) ) {
                            if ( elem.nodetype === 1 || checknonelements ) {
                                if ( matcher( elem, context, xml ) ) {
                                    return true;
                                }
                            }
                        }
                    } else {
                        while ( (elem = elem[ dir ]) ) {
                            if ( elem.nodetype === 1 || checknonelements ) {
                                outercache = elem[ expando ] || (elem[ expando ] = {});
                                if ( (cache = outercache[ dir ]) && cache[0] === dirkey ) {
                                    if ( (data = cache[1]) === true || data === cachedruns ) {
                                        return data === true;
                                    }
                                } else {
                                    cache = outercache[ dir ] = [ dirkey ];
                                    cache[1] = matcher( elem, context, xml ) || cachedruns;
                                    if ( cache[1] === true ) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                };
        }

        function elementmatcher( matchers ) {
            return matchers.length > 1 ?
                function( elem, context, xml ) {
                    var i = matchers.length;
                    while ( i-- ) {
                        if ( !matchers[i]( elem, context, xml ) ) {
                            return false;
                        }
                    }
                    return true;
                } :
                matchers[0];
        }

        function condense( unmatched, map, filter, context, xml ) {
            var elem,
                newunmatched = [],
                i = 0,
                len = unmatched.length,
                mapped = map != null;

            for ( ; i < len; i++ ) {
                if ( (elem = unmatched[i]) ) {
                    if ( !filter || filter( elem, context, xml ) ) {
                        newunmatched.push( elem );
                        if ( mapped ) {
                            map.push( i );
                        }
                    }
                }
            }

            return newunmatched;
        }

        function setmatcher( prefilter, selector, matcher, postfilter, postfinder, postselector ) {
            if ( postfilter && !postfilter[ expando ] ) {
                postfilter = setmatcher( postfilter );
            }
            if ( postfinder && !postfinder[ expando ] ) {
                postfinder = setmatcher( postfinder, postselector );
            }
            return markfunction(function( seed, results, context, xml ) {
                var temp, i, elem,
                    premap = [],
                    postmap = [],
                    preexisting = results.length,

                // get initial elements from seed or context
                    elems = seed || multiplecontexts( selector || "*", context.nodetype ? [ context ] : context, [] ),

                // prefilter to get matcher input, preserving a map for seed-results synchronization
                    matcherin = prefilter && ( seed || !selector ) ?
                        condense( elems, premap, prefilter, context, xml ) :
                        elems,

                    matcherout = matcher ?
                        // if we have a postfinder, or filtered seed, or non-seed postfilter or preexisting results,
                            postfinder || ( seed ? prefilter : preexisting || postfilter ) ?

                        // ...intermediate processing is necessary
                        [] :

                        // ...otherwise use results directly
                        results :
                        matcherin;

                // find primary matches
                if ( matcher ) {
                    matcher( matcherin, matcherout, context, xml );
                }

                // apply postfilter
                if ( postfilter ) {
                    temp = condense( matcherout, postmap );
                    postfilter( temp, [], context, xml );

                    // un-match failing elements by moving them back to matcherin
                    i = temp.length;
                    while ( i-- ) {
                        if ( (elem = temp[i]) ) {
                            matcherout[ postmap[i] ] = !(matcherin[ postmap[i] ] = elem);
                        }
                    }
                }

                if ( seed ) {
                    if ( postfinder || prefilter ) {
                        if ( postfinder ) {
                            // get the final matcherout by condensing this intermediate into postfinder contexts
                            temp = [];
                            i = matcherout.length;
                            while ( i-- ) {
                                if ( (elem = matcherout[i]) ) {
                                    // restore matcherin since elem is not yet a final match
                                    temp.push( (matcherin[i] = elem) );
                                }
                            }
                            postfinder( null, (matcherout = []), temp, xml );
                        }

                        // move matched elements from seed to results to keep them synchronized
                        i = matcherout.length;
                        while ( i-- ) {
                            if ( (elem = matcherout[i]) &&
                                (temp = postfinder ? indexof.call( seed, elem ) : premap[i]) > -1 ) {

                                seed[temp] = !(results[temp] = elem);
                            }
                        }
                    }

                    // add elements to results, through postfinder if defined
                } else {
                    matcherout = condense(
                            matcherout === results ?
                            matcherout.splice( preexisting, matcherout.length ) :
                            matcherout
                    );
                    if ( postfinder ) {
                        postfinder( null, results, matcherout, xml );
                    } else {
                        push.apply( results, matcherout );
                    }
                }
            });
        }

        function matcherfromtokens( tokens ) {
            var checkcontext, matcher, j,
                len = tokens.length,
                leadingrelative = expr.relative[ tokens[0].type ],
                implicitrelative = leadingrelative || expr.relative[" "],
                i = leadingrelative ? 1 : 0,

            // the foundational matcher ensures that elements are reachable from top-level context(s)
                matchcontext = addcombinator( function( elem ) {
                    return elem === checkcontext;
                }, implicitrelative, true ),
                matchanycontext = addcombinator( function( elem ) {
                    return indexof.call( checkcontext, elem ) > -1;
                }, implicitrelative, true ),
                matchers = [ function( elem, context, xml ) {
                    return ( !leadingrelative && ( xml || context !== outermostcontext ) ) || (
                        (checkcontext = context).nodetype ?
                            matchcontext( elem, context, xml ) :
                            matchanycontext( elem, context, xml ) );
                } ];

            for ( ; i < len; i++ ) {
                if ( (matcher = expr.relative[ tokens[i].type ]) ) {
                    matchers = [ addcombinator(elementmatcher( matchers ), matcher) ];
                } else {
                    matcher = expr.filter[ tokens[i].type ].apply( null, tokens[i].matches );

                    // return special upon seeing a positional matcher
                    if ( matcher[ expando ] ) {
                        // find the next relative operator (if any) for proper handling
                        j = ++i;
                        for ( ; j < len; j++ ) {
                            if ( expr.relative[ tokens[j].type ] ) {
                                break;
                            }
                        }
                        return setmatcher(
                                i > 1 && elementmatcher( matchers ),
                                i > 1 && toselector(
                                // if the preceding token was a descendant combinator, insert an implicit any-element `*`
                                tokens.slice( 0, i - 1 ).concat({ value: tokens[ i - 2 ].type === " " ? "*" : "" })
                            ).replace( rtrim, "$1" ),
                            matcher,
                                i < j && matcherfromtokens( tokens.slice( i, j ) ),
                                j < len && matcherfromtokens( (tokens = tokens.slice( j )) ),
                                j < len && toselector( tokens )
                        );
                    }
                    matchers.push( matcher );
                }
            }

            return elementmatcher( matchers );
        }

        function matcherfromgroupmatchers( elementmatchers, setmatchers ) {
            // a counter to specify which element is currently being matched
            var matchercachedruns = 0,
                byset = setmatchers.length > 0,
                byelement = elementmatchers.length > 0,
                supermatcher = function( seed, context, xml, results, expandcontext ) {
                    var elem, j, matcher,
                        setmatched = [],
                        matchedcount = 0,
                        i = "0",
                        unmatched = seed && [],
                        outermost = expandcontext != null,
                        contextbackup = outermostcontext,
                    // we must always have either seed elements or context
                        elems = seed || byelement && expr.find["tag"]( "*", expandcontext && context.parentnode || context ),
                    // use integer dirruns iff this is the outermost matcher
                        dirrunsunique = (dirruns += contextbackup == null ? 1 : math.random() || 0.1);

                    if ( outermost ) {
                        outermostcontext = context !== document && context;
                        cachedruns = matchercachedruns;
                    }

                    // add elements passing elementmatchers directly to results
                    // keep `i` a string if there are no elements so `matchedcount` will be "00" below
                    for ( ; (elem = elems[i]) != null; i++ ) {
                        if ( byelement && elem ) {
                            j = 0;
                            while ( (matcher = elementmatchers[j++]) ) {
                                if ( matcher( elem, context, xml ) ) {
                                    results.push( elem );
                                    break;
                                }
                            }
                            if ( outermost ) {
                                dirruns = dirrunsunique;
                                cachedruns = ++matchercachedruns;
                            }
                        }

                        // track unmatched elements for set filters
                        if ( byset ) {
                            // they will have gone through all possible matchers
                            if ( (elem = !matcher && elem) ) {
                                matchedcount--;
                            }

                            // lengthen the array for every element, matched or not
                            if ( seed ) {
                                unmatched.push( elem );
                            }
                        }
                    }

                    // apply set filters to unmatched elements
                    matchedcount += i;
                    if ( byset && i !== matchedcount ) {
                        j = 0;
                        while ( (matcher = setmatchers[j++]) ) {
                            matcher( unmatched, setmatched, context, xml );
                        }

                        if ( seed ) {
                            // reintegrate element matches to eliminate the need for sorting
                            if ( matchedcount > 0 ) {
                                while ( i-- ) {
                                    if ( !(unmatched[i] || setmatched[i]) ) {
                                        setmatched[i] = pop.call( results );
                                    }
                                }
                            }

                            // discard index placeholder values to get only actual matches
                            setmatched = condense( setmatched );
                        }

                        // add matches to results
                        push.apply( results, setmatched );

                        // seedless set matches succeeding multiple successful matchers stipulate sorting
                        if ( outermost && !seed && setmatched.length > 0 &&
                            ( matchedcount + setmatchers.length ) > 1 ) {

                            sizzle.uniquesort( results );
                        }
                    }

                    // override manipulation of globals by nested matchers
                    if ( outermost ) {
                        dirruns = dirrunsunique;
                        outermostcontext = contextbackup;
                    }

                    return unmatched;
                };

            return byset ?
                markfunction( supermatcher ) :
                supermatcher;
        }

        compile = sizzle.compile = function( selector, group /* internal use only */ ) {
            var i,
                setmatchers = [],
                elementmatchers = [],
                cached = compilercache[ selector + " " ];

            if ( !cached ) {
                // generate a function of recursive functions that can be used to check each element
                if ( !group ) {
                    group = tokenize( selector );
                }
                i = group.length;
                while ( i-- ) {
                    cached = matcherfromtokens( group[i] );
                    if ( cached[ expando ] ) {
                        setmatchers.push( cached );
                    } else {
                        elementmatchers.push( cached );
                    }
                }

                // cache the compiled function
                cached = compilercache( selector, matcherfromgroupmatchers( elementmatchers, setmatchers ) );
            }
            return cached;
        };

        function multiplecontexts( selector, contexts, results ) {
            var i = 0,
                len = contexts.length;
            for ( ; i < len; i++ ) {
                sizzle( selector, contexts[i], results );
            }
            return results;
        }

        function select( selector, context, results, seed ) {
            var i, tokens, token, type, find,
                match = tokenize( selector );

            if ( !seed ) {
                // try to minimize operations if there is only one group
                if ( match.length === 1 ) {

                    // take a shortcut and set the context if the root selector is an id
                    tokens = match[0] = match[0].slice( 0 );
                    if ( tokens.length > 2 && (token = tokens[0]).type === "id" &&
                        support.getbyid && context.nodetype === 9 && documentishtml &&
                        expr.relative[ tokens[1].type ] ) {

                        context = ( expr.find["id"]( token.matches[0].replace(runescape, funescape), context ) || [] )[0];
                        if ( !context ) {
                            return results;
                        }
                        selector = selector.slice( tokens.shift().value.length );
                    }

                    // fetch a seed set for right-to-left matching
                    i = matchexpr["needscontext"].test( selector ) ? 0 : tokens.length;
                    while ( i-- ) {
                        token = tokens[i];

                        // abort if we hit a combinator
                        if ( expr.relative[ (type = token.type) ] ) {
                            break;
                        }
                        if ( (find = expr.find[ type ]) ) {
                            // search, expanding context for leading sibling combinators
                            if ( (seed = find(
                                token.matches[0].replace( runescape, funescape ),
                                    rsibling.test( tokens[0].type ) && context.parentnode || context
                            )) ) {

                                // if seed is empty or no tokens remain, we can return early
                                tokens.splice( i, 1 );
                                selector = seed.length && toselector( tokens );
                                if ( !selector ) {
                                    push.apply( results, seed );
                                    return results;
                                }

                                break;
                            }
                        }
                    }
                }
            }

            // compile and execute a filtering function
            // provide `match` to avoid retokenization if we modified the selector above
            compile( selector, match )(
                seed,
                context,
                !documentishtml,
                results,
                rsibling.test( selector )
            );
            return results;
        }

// one-time assignments

// sort stability
        support.sortstable = expando.split("").sort( sortorder ).join("") === expando;

// support: chrome<14
// always assume duplicates if they aren't passed to the comparison function
        support.detectduplicates = hasduplicate;

// initialize against the default document
        setdocument();

// support: webkit<537.32 - safari 6.0.3/chrome 25 (fixed in chrome 27)
// detached nodes confoundingly follow *each other*
        support.sortdetached = assert(function( div1 ) {
            // should return 1, but returns 4 (following)
            return div1.comparedocumentposition( document.createelement("div") ) & 1;
        });

// support: ie<8
// prevent attribute/property "interpolation"
// http://msdn.microsoft.com/en-us/library/ms536429%28vs.85%29.aspx
        if ( !assert(function( div ) {
            div.innerhtml = "<a href='#'></a>";
            return div.firstchild.getattribute("href") === "#" ;
        }) ) {
            addhandle( "type|href|height|width", function( elem, name, isxml ) {
                if ( !isxml ) {
                    return elem.getattribute( name, name.tolowercase() === "type" ? 1 : 2 );
                }
            });
        }

// support: ie<9
// use defaultvalue in place of getattribute("value")
        if ( !support.attributes || !assert(function( div ) {
            div.innerhtml = "<input/>";
            div.firstchild.setattribute( "value", "" );
            return div.firstchild.getattribute( "value" ) === "";
        }) ) {
            addhandle( "value", function( elem, name, isxml ) {
                if ( !isxml && elem.nodename.tolowercase() === "input" ) {
                    return elem.defaultvalue;
                }
            });
        }

// support: ie<9
// use getattributenode to fetch booleans when getattribute lies
        if ( !assert(function( div ) {
            return div.getattribute("disabled") == null;
        }) ) {
            addhandle( booleans, function( elem, name, isxml ) {
                var val;
                if ( !isxml ) {
                    return (val = elem.getattributenode( name )) && val.specified ?
                        val.value :
                            elem[ name ] === true ? name.tolowercase() : null;
                }
            });
        }

        jquery.find = sizzle;
        jquery.expr = sizzle.selectors;
        jquery.expr[":"] = jquery.expr.pseudos;
        jquery.unique = sizzle.uniquesort;
        jquery.text = sizzle.gettext;
        jquery.isxmldoc = sizzle.isxml;
        jquery.contains = sizzle.contains;


    })( window );
// string to object options format cache
    var optionscache = {};

// convert string-formatted options into object-formatted ones and store in cache
    function createoptions( options ) {
        var object = optionscache[ options ] = {};
        jquery.each( options.match( core_rnotwhite ) || [], function( _, flag ) {
            object[ flag ] = true;
        });
        return object;
    }

    /*
     * create a callback list using the following parameters:
     *
     *	options: an optional list of space-separated options that will change how
     *			the callback list behaves or a more traditional option object
     *
     * by default a callback list will act like an event callback list and can be
     * "fired" multiple times.
     *
     * possible options:
     *
     *	once:			will ensure the callback list can only be fired once (like a deferred)
     *
     *	memory:			will keep track of previous values and will call any callback added
     *					after the list has been fired right away with the latest "memorized"
     *					values (like a deferred)
     *
     *	unique:			will ensure a callback can only be added once (no duplicate in the list)
     *
     *	stoponfalse:	interrupt callings when a callback returns false
     *
     */
    jquery.callbacks = function( options ) {

        // convert options from string-formatted to object-formatted if needed
        // (we check in cache first)
        options = typeof options === "string" ?
            ( optionscache[ options ] || createoptions( options ) ) :
            jquery.extend( {}, options );

        var // flag to know if list is currently firing
            firing,
        // last fire value (for non-forgettable lists)
            memory,
        // flag to know if list was already fired
            fired,
        // end of the loop when firing
            firinglength,
        // index of currently firing callback (modified by remove if needed)
            firingindex,
        // first callback to fire (used internally by add and firewith)
            firingstart,
        // actual callback list
            list = [],
        // stack of fire calls for repeatable lists
            stack = !options.once && [],
        // fire callbacks
            fire = function( data ) {
                memory = options.memory && data;
                fired = true;
                firingindex = firingstart || 0;
                firingstart = 0;
                firinglength = list.length;
                firing = true;
                for ( ; list && firingindex < firinglength; firingindex++ ) {
                    if ( list[ firingindex ].apply( data[ 0 ], data[ 1 ] ) === false && options.stoponfalse ) {
                        memory = false; // to prevent further calls using add
                        break;
                    }
                }
                firing = false;
                if ( list ) {
                    if ( stack ) {
                        if ( stack.length ) {
                            fire( stack.shift() );
                        }
                    } else if ( memory ) {
                        list = [];
                    } else {
                        self.disable();
                    }
                }
            },
        // actual callbacks object
            self = {
                // add a callback or a collection of callbacks to the list
                add: function() {
                    if ( list ) {
                        // first, we save the current length
                        var start = list.length;
                        (function add( args ) {
                            jquery.each( args, function( _, arg ) {
                                var type = jquery.type( arg );
                                if ( type === "function" ) {
                                    if ( !options.unique || !self.has( arg ) ) {
                                        list.push( arg );
                                    }
                                } else if ( arg && arg.length && type !== "string" ) {
                                    // inspect recursively
                                    add( arg );
                                }
                            });
                        })( arguments );
                        // do we need to add the callbacks to the
                        // current firing batch?
                        if ( firing ) {
                            firinglength = list.length;
                            // with memory, if we're not firing then
                            // we should call right away
                        } else if ( memory ) {
                            firingstart = start;
                            fire( memory );
                        }
                    }
                    return this;
                },
                // remove a callback from the list
                remove: function() {
                    if ( list ) {
                        jquery.each( arguments, function( _, arg ) {
                            var index;
                            while( ( index = jquery.inarray( arg, list, index ) ) > -1 ) {
                                list.splice( index, 1 );
                                // handle firing indexes
                                if ( firing ) {
                                    if ( index <= firinglength ) {
                                        firinglength--;
                                    }
                                    if ( index <= firingindex ) {
                                        firingindex--;
                                    }
                                }
                            }
                        });
                    }
                    return this;
                },
                // check if a given callback is in the list.
                // if no argument is given, return whether or not list has callbacks attached.
                has: function( fn ) {
                    return fn ? jquery.inarray( fn, list ) > -1 : !!( list && list.length );
                },
                // remove all callbacks from the list
                empty: function() {
                    list = [];
                    firinglength = 0;
                    return this;
                },
                // have the list do nothing anymore
                disable: function() {
                    list = stack = memory = undefined;
                    return this;
                },
                // is it disabled?
                disabled: function() {
                    return !list;
                },
                // lock the list in its current state
                lock: function() {
                    stack = undefined;
                    if ( !memory ) {
                        self.disable();
                    }
                    return this;
                },
                // is it locked?
                locked: function() {
                    return !stack;
                },
                // call all callbacks with the given context and arguments
                firewith: function( context, args ) {
                    if ( list && ( !fired || stack ) ) {
                        args = args || [];
                        args = [ context, args.slice ? args.slice() : args ];
                        if ( firing ) {
                            stack.push( args );
                        } else {
                            fire( args );
                        }
                    }
                    return this;
                },
                // call all the callbacks with the given arguments
                fire: function() {
                    self.firewith( this, arguments );
                    return this;
                },
                // to know if the callbacks have already been called at least once
                fired: function() {
                    return !!fired;
                }
            };

        return self;
    };
    jquery.extend({

        deferred: function( func ) {
            var tuples = [
                    // action, add listener, listener list, final state
                    [ "resolve", "done", jquery.callbacks("once memory"), "resolved" ],
                    [ "reject", "fail", jquery.callbacks("once memory"), "rejected" ],
                    [ "notify", "progress", jquery.callbacks("memory") ]
                ],
                state = "pending",
                promise = {
                    state: function() {
                        return state;
                    },
                    always: function() {
                        deferred.done( arguments ).fail( arguments );
                        return this;
                    },
                    then: function( /* fndone, fnfail, fnprogress */ ) {
                        var fns = arguments;
                        return jquery.deferred(function( newdefer ) {
                            jquery.each( tuples, function( i, tuple ) {
                                var action = tuple[ 0 ],
                                    fn = jquery.isfunction( fns[ i ] ) && fns[ i ];
                                // deferred[ done | fail | progress ] for forwarding actions to newdefer
                                deferred[ tuple[1] ](function() {
                                    var returned = fn && fn.apply( this, arguments );
                                    if ( returned && jquery.isfunction( returned.promise ) ) {
                                        returned.promise()
                                            .done( newdefer.resolve )
                                            .fail( newdefer.reject )
                                            .progress( newdefer.notify );
                                    } else {
                                        newdefer[ action + "with" ]( this === promise ? newdefer.promise() : this, fn ? [ returned ] : arguments );
                                    }
                                });
                            });
                            fns = null;
                        }).promise();
                    },
                    // get a promise for this deferred
                    // if obj is provided, the promise aspect is added to the object
                    promise: function( obj ) {
                        return obj != null ? jquery.extend( obj, promise ) : promise;
                    }
                },
                deferred = {};

            // keep pipe for back-compat
            promise.pipe = promise.then;

            // add list-specific methods
            jquery.each( tuples, function( i, tuple ) {
                var list = tuple[ 2 ],
                    statestring = tuple[ 3 ];

                // promise[ done | fail | progress ] = list.add
                promise[ tuple[1] ] = list.add;

                // handle state
                if ( statestring ) {
                    list.add(function() {
                        // state = [ resolved | rejected ]
                        state = statestring;

                        // [ reject_list | resolve_list ].disable; progress_list.lock
                    }, tuples[ i ^ 1 ][ 2 ].disable, tuples[ 2 ][ 2 ].lock );
                }

                // deferred[ resolve | reject | notify ]
                deferred[ tuple[0] ] = function() {
                    deferred[ tuple[0] + "with" ]( this === deferred ? promise : this, arguments );
                    return this;
                };
                deferred[ tuple[0] + "with" ] = list.firewith;
            });

            // make the deferred a promise
            promise.promise( deferred );

            // call given func if any
            if ( func ) {
                func.call( deferred, deferred );
            }

            // all done!
            return deferred;
        },

        // deferred helper
        when: function( subordinate /* , ..., subordinaten */ ) {
            var i = 0,
                resolvevalues = core_slice.call( arguments ),
                length = resolvevalues.length,

            // the count of uncompleted subordinates
                remaining = length !== 1 || ( subordinate && jquery.isfunction( subordinate.promise ) ) ? length : 0,

            // the master deferred. if resolvevalues consist of only a single deferred, just use that.
                deferred = remaining === 1 ? subordinate : jquery.deferred(),

            // update function for both resolve and progress values
                updatefunc = function( i, contexts, values ) {
                    return function( value ) {
                        contexts[ i ] = this;
                        values[ i ] = arguments.length > 1 ? core_slice.call( arguments ) : value;
                        if( values === progressvalues ) {
                            deferred.notifywith( contexts, values );
                        } else if ( !( --remaining ) ) {
                            deferred.resolvewith( contexts, values );
                        }
                    };
                },

                progressvalues, progresscontexts, resolvecontexts;

            // add listeners to deferred subordinates; treat others as resolved
            if ( length > 1 ) {
                progressvalues = new array( length );
                progresscontexts = new array( length );
                resolvecontexts = new array( length );
                for ( ; i < length; i++ ) {
                    if ( resolvevalues[ i ] && jquery.isfunction( resolvevalues[ i ].promise ) ) {
                        resolvevalues[ i ].promise()
                            .done( updatefunc( i, resolvecontexts, resolvevalues ) )
                            .fail( deferred.reject )
                            .progress( updatefunc( i, progresscontexts, progressvalues ) );
                    } else {
                        --remaining;
                    }
                }
            }

            // if we're not waiting on anything, resolve the master
            if ( !remaining ) {
                deferred.resolvewith( resolvecontexts, resolvevalues );
            }

            return deferred.promise();
        }
    });
    jquery.support = (function( support ) {

        var all, a, input, select, fragment, opt, eventname, issupported, i,
            div = document.createelement("div");

        // setup
        div.setattribute( "classname", "t" );
        div.innerhtml = "  <link/><table></table><a href='/a'>a</a><input type='checkbox'/>";

        // finish early in limited (non-browser) environments
        all = div.getelementsbytagname("*") || [];
        a = div.getelementsbytagname("a")[ 0 ];
        if ( !a || !a.style || !all.length ) {
            return support;
        }

        // first batch of tests
        select = document.createelement("select");
        opt = select.appendchild( document.createelement("option") );
        input = div.getelementsbytagname("input")[ 0 ];

        a.style.csstext = "top:1px;float:left;opacity:.5";

        // test setattribute on camelcase class. if it works, we need attrfixes when doing get/setattribute (ie6/7)
        support.getsetattribute = div.classname !== "t";

        // ie strips leading whitespace when .innerhtml is used
        support.leadingwhitespace = div.firstchild.nodetype === 3;

        // make sure that tbody elements aren't automatically inserted
        // ie will insert them into empty tables
        support.tbody = !div.getelementsbytagname("tbody").length;

        // make sure that link elements get serialized correctly by innerhtml
        // this requires a wrapper element in ie
        support.htmlserialize = !!div.getelementsbytagname("link").length;

        // get the style information from getattribute
        // (ie uses .csstext instead)
        support.style = /top/.test( a.getattribute("style") );

        // make sure that urls aren't manipulated
        // (ie normalizes it by default)
        support.hrefnormalized = a.getattribute("href") === "/a";

        // make sure that element opacity exists
        // (ie uses filter instead)
        // use a regex to work around a webkit issue. see #5145
        support.opacity = /^0.5/.test( a.style.opacity );

        // verify style float existence
        // (ie uses stylefloat instead of cssfloat)
        support.cssfloat = !!a.style.cssfloat;

        // check the default checkbox/radio value ("" on webkit; "on" elsewhere)
        support.checkon = !!input.value;

        // make sure that a selected-by-default option has a working selected property.
        // (webkit defaults to false instead of true, ie too, if it's in an optgroup)
        support.optselected = opt.selected;

        // tests for enctype support on a form (#6743)
        support.enctype = !!document.createelement("form").enctype;

        // makes sure cloning an html5 element does not cause problems
        // where outerhtml is undefined, this still works
        support.html5clone = document.createelement("nav").clonenode( true ).outerhtml !== "<:nav></:nav>";

        // will be defined later
        support.inlineblockneedslayout = false;
        support.shrinkwrapblocks = false;
        support.pixelposition = false;
        support.deleteexpando = true;
        support.nocloneevent = true;
        support.reliablemarginright = true;
        support.boxsizingreliable = true;

        // make sure checked status is properly cloned
        input.checked = true;
        support.noclonechecked = input.clonenode( true ).checked;

        // make sure that the options inside disabled selects aren't marked as disabled
        // (webkit marks them as disabled)
        select.disabled = true;
        support.optdisabled = !opt.disabled;

        // support: ie<9
        try {
            delete div.test;
        } catch( e ) {
            support.deleteexpando = false;
        }

        // check if we can trust getattribute("value")
        input = document.createelement("input");
        input.setattribute( "value", "" );
        support.input = input.getattribute( "value" ) === "";

        // check if an input maintains its value after becoming a radio
        input.value = "t";
        input.setattribute( "type", "radio" );
        support.radiovalue = input.value === "t";

        // #11217 - webkit loses check when the name is after the checked attribute
        input.setattribute( "checked", "t" );
        input.setattribute( "name", "t" );

        fragment = document.createdocumentfragment();
        fragment.appendchild( input );

        // check if a disconnected checkbox will retain its checked
        // value of true after appended to the dom (ie6/7)
        support.appendchecked = input.checked;

        // webkit doesn't clone checked state correctly in fragments
        support.checkclone = fragment.clonenode( true ).clonenode( true ).lastchild.checked;

        // support: ie<9
        // opera does not clone events (and typeof div.attachevent === undefined).
        // ie9-10 clones events bound via attachevent, but they don't trigger with .click()
        if ( div.attachevent ) {
            div.attachevent( "onclick", function() {
                support.nocloneevent = false;
            });

            div.clonenode( true ).click();
        }

        // support: ie<9 (lack submit/change bubble), firefox 17+ (lack focusin event)
        // beware of csp restrictions (https://developer.mozilla.org/en/security/csp)
        for ( i in { submit: true, change: true, focusin: true }) {
            div.setattribute( eventname = "on" + i, "t" );

            support[ i + "bubbles" ] = eventname in window || div.attributes[ eventname ].expando === false;
        }

        div.style.backgroundclip = "content-box";
        div.clonenode( true ).style.backgroundclip = "";
        support.clearclonestyle = div.style.backgroundclip === "content-box";

        // support: ie<9
        // iteration over object's inherited properties before its own.
        for ( i in jquery( support ) ) {
            break;
        }
        support.ownlast = i !== "0";

        // run tests that need a body at doc ready
        jquery(function() {
            var container, margindiv, tds,
                divreset = "padding:0;margin:0;border:0;display:block;box-sizing:content-box;-moz-box-sizing:content-box;-webkit-box-sizing:content-box;",
                body = document.getelementsbytagname("body")[0];

            if ( !body ) {
                // return for frameset docs that don't have a body
                return;
            }

            container = document.createelement("div");
            container.style.csstext = "border:0;width:0;height:0;position:absolute;top:0;left:-9999px;margin-top:1px";

            body.appendchild( container ).appendchild( div );

            // support: ie8
            // check if table cells still have offsetwidth/height when they are set
            // to display:none and there are still other visible table cells in a
            // table row; if so, offsetwidth/height are not reliable for use when
            // determining if an element has been hidden directly using
            // display:none (it is still safe to use offsets if a parent element is
            // hidden; don safety goggles and see bug #4512 for more information).
            div.innerhtml = "<table><tr><td></td><td>t</td></tr></table>";
            tds = div.getelementsbytagname("td");
            tds[ 0 ].style.csstext = "padding:0;margin:0;border:0;display:none";
            issupported = ( tds[ 0 ].offsetheight === 0 );

            tds[ 0 ].style.display = "";
            tds[ 1 ].style.display = "none";

            // support: ie8
            // check if empty table cells still have offsetwidth/height
            support.reliablehiddenoffsets = issupported && ( tds[ 0 ].offsetheight === 0 );

            // check box-sizing and margin behavior.
            div.innerhtml = "";
            div.style.csstext = "box-sizing:border-box;-moz-box-sizing:border-box;-webkit-box-sizing:border-box;padding:1px;border:1px;display:block;width:4px;margin-top:1%;position:absolute;top:1%;";

            // workaround failing boxsizing test due to offsetwidth returning wrong value
            // with some non-1 values of body zoom, ticket #13543
            jquery.swap( body, body.style.zoom != null ? { zoom: 1 } : {}, function() {
                support.boxsizing = div.offsetwidth === 4;
            });

            // use window.getcomputedstyle because jsdom on node.js will break without it.
            if ( window.getcomputedstyle ) {
                support.pixelposition = ( window.getcomputedstyle( div, null ) || {} ).top !== "1%";
                support.boxsizingreliable = ( window.getcomputedstyle( div, null ) || { width: "4px" } ).width === "4px";

                // check if div with explicit width and no margin-right incorrectly
                // gets computed margin-right based on width of container. (#3333)
                // fails in webkit before feb 2011 nightlies
                // webkit bug 13343 - getcomputedstyle returns wrong value for margin-right
                margindiv = div.appendchild( document.createelement("div") );
                margindiv.style.csstext = div.style.csstext = divreset;
                margindiv.style.marginright = margindiv.style.width = "0";
                div.style.width = "1px";

                support.reliablemarginright =
                    !parsefloat( ( window.getcomputedstyle( margindiv, null ) || {} ).marginright );
            }

            if ( typeof div.style.zoom !== core_strundefined ) {
                // support: ie<8
                // check if natively block-level elements act like inline-block
                // elements when setting their display to 'inline' and giving
                // them layout
                div.innerhtml = "";
                div.style.csstext = divreset + "width:1px;padding:1px;display:inline;zoom:1";
                support.inlineblockneedslayout = ( div.offsetwidth === 3 );

                // support: ie6
                // check if elements with layout shrink-wrap their children
                div.style.display = "block";
                div.innerhtml = "<div></div>";
                div.firstchild.style.width = "5px";
                support.shrinkwrapblocks = ( div.offsetwidth !== 3 );

                if ( support.inlineblockneedslayout ) {
                    // prevent ie 6 from affecting layout for positioned elements #11048
                    // prevent ie from shrinking the body in ie 7 mode #12869
                    // support: ie<8
                    body.style.zoom = 1;
                }
            }

            body.removechild( container );

            // null elements to avoid leaks in ie
            container = div = tds = margindiv = null;
        });

        // null elements to avoid leaks in ie
        all = select = fragment = opt = a = input = null;

        return support;
    })({});

    var rbrace = /(?:\{[\s\s]*\}|\[[\s\s]*\])$/,
        rmultidash = /([a-z])/g;

    function internaldata( elem, name, data, pvt /* internal use only */ ){
        if ( !jquery.acceptdata( elem ) ) {
            return;
        }

        var ret, thiscache,
            internalkey = jquery.expando,

        // we have to handle dom nodes and js objects differently because ie6-7
        // can't gc object references properly across the dom-js boundary
            isnode = elem.nodetype,

        // only dom nodes need the global jquery cache; js object data is
        // attached directly to the object so gc can occur automatically
            cache = isnode ? jquery.cache : elem,

        // only defining an id for js objects if its cache already exists allows
        // the code to shortcut on the same path as a dom node with no cache
            id = isnode ? elem[ internalkey ] : elem[ internalkey ] && internalkey;

        // avoid doing any more work than we need to when trying to get data on an
        // object that has no data at all
        if ( (!id || !cache[id] || (!pvt && !cache[id].data)) && data === undefined && typeof name === "string" ) {
            return;
        }

        if ( !id ) {
            // only dom nodes need a new unique id for each element since their data
            // ends up in the global cache
            if ( isnode ) {
                id = elem[ internalkey ] = core_deletedids.pop() || jquery.guid++;
            } else {
                id = internalkey;
            }
        }

        if ( !cache[ id ] ) {
            // avoid exposing jquery metadata on plain js objects when the object
            // is serialized using json.stringify
            cache[ id ] = isnode ? {} : { tojson: jquery.noop };
        }

        // an object can be passed to jquery.data instead of a key/value pair; this gets
        // shallow copied over onto the existing cache
        if ( typeof name === "object" || typeof name === "function" ) {
            if ( pvt ) {
                cache[ id ] = jquery.extend( cache[ id ], name );
            } else {
                cache[ id ].data = jquery.extend( cache[ id ].data, name );
            }
        }

        thiscache = cache[ id ];

        // jquery data() is stored in a separate object inside the object's internal data
        // cache in order to avoid key collisions between internal data and user-defined
        // data.
        if ( !pvt ) {
            if ( !thiscache.data ) {
                thiscache.data = {};
            }

            thiscache = thiscache.data;
        }

        if ( data !== undefined ) {
            thiscache[ jquery.camelcase( name ) ] = data;
        }

        // check for both converted-to-camel and non-converted data property names
        // if a data property was specified
        if ( typeof name === "string" ) {

            // first try to find as-is property data
            ret = thiscache[ name ];

            // test for null|undefined property data
            if ( ret == null ) {

                // try to find the camelcased property
                ret = thiscache[ jquery.camelcase( name ) ];
            }
        } else {
            ret = thiscache;
        }

        return ret;
    }

    function internalremovedata( elem, name, pvt ) {
        if ( !jquery.acceptdata( elem ) ) {
            return;
        }

        var thiscache, i,
            isnode = elem.nodetype,

        // see jquery.data for more information
            cache = isnode ? jquery.cache : elem,
            id = isnode ? elem[ jquery.expando ] : jquery.expando;

        // if there is already no cache entry for this object, there is no
        // purpose in continuing
        if ( !cache[ id ] ) {
            return;
        }

        if ( name ) {

            thiscache = pvt ? cache[ id ] : cache[ id ].data;

            if ( thiscache ) {

                // support array or space separated string names for data keys
                if ( !jquery.isarray( name ) ) {

                    // try the string as a key before any manipulation
                    if ( name in thiscache ) {
                        name = [ name ];
                    } else {

                        // split the camel cased version by spaces unless a key with the spaces exists
                        name = jquery.camelcase( name );
                        if ( name in thiscache ) {
                            name = [ name ];
                        } else {
                            name = name.split(" ");
                        }
                    }
                } else {
                    // if "name" is an array of keys...
                    // when data is initially created, via ("key", "val") signature,
                    // keys will be converted to camelcase.
                    // since there is no way to tell _how_ a key was added, remove
                    // both plain key and camelcase key. #12786
                    // this will only penalize the array argument path.
                    name = name.concat( jquery.map( name, jquery.camelcase ) );
                }

                i = name.length;
                while ( i-- ) {
                    delete thiscache[ name[i] ];
                }

                // if there is no data left in the cache, we want to continue
                // and let the cache object itself get destroyed
                if ( pvt ? !isemptydataobject(thiscache) : !jquery.isemptyobject(thiscache) ) {
                    return;
                }
            }
        }

        // see jquery.data for more information
        if ( !pvt ) {
            delete cache[ id ].data;

            // don't destroy the parent cache unless the internal data object
            // had been the only thing left in it
            if ( !isemptydataobject( cache[ id ] ) ) {
                return;
            }
        }

        // destroy the cache
        if ( isnode ) {
            jquery.cleandata( [ elem ], true );

            // use delete when supported for expandos or `cache` is not a window per iswindow (#10080)
            /* jshint eqeqeq: false */
        } else if ( jquery.support.deleteexpando || cache != cache.window ) {
            /* jshint eqeqeq: true */
            delete cache[ id ];

            // when all else fails, null
        } else {
            cache[ id ] = null;
        }
    }

    jquery.extend({
        cache: {},

        // the following elements throw uncatchable exceptions if you
        // attempt to add expando properties to them.
        nodata: {
            "applet": true,
            "embed": true,
            // ban all objects except for flash (which handle expandos)
            "object": "clsid:d27cdb6e-ae6d-11cf-96b8-444553540000"
        },

        hasdata: function( elem ) {
            elem = elem.nodetype ? jquery.cache[ elem[jquery.expando] ] : elem[ jquery.expando ];
            return !!elem && !isemptydataobject( elem );
        },

        data: function( elem, name, data ) {
            return internaldata( elem, name, data );
        },

        removedata: function( elem, name ) {
            return internalremovedata( elem, name );
        },

        // for internal use only.
        _data: function( elem, name, data ) {
            return internaldata( elem, name, data, true );
        },

        _removedata: function( elem, name ) {
            return internalremovedata( elem, name, true );
        },

        // a method for determining if a dom node can handle the data expando
        acceptdata: function( elem ) {
            // do not set data on non-element because it will not be cleared (#8335).
            if ( elem.nodetype && elem.nodetype !== 1 && elem.nodetype !== 9 ) {
                return false;
            }

            var nodata = elem.nodename && jquery.nodata[ elem.nodename.tolowercase() ];

            // nodes accept data unless otherwise specified; rejection can be conditional
            return !nodata || nodata !== true && elem.getattribute("classid") === nodata;
        }
    });

    jquery.fn.extend({
        data: function( key, value ) {
            var attrs, name,
                data = null,
                i = 0,
                elem = this[0];

            // special expections of .data basically thwart jquery.access,
            // so implement the relevant behavior ourselves

            // gets all values
            if ( key === undefined ) {
                if ( this.length ) {
                    data = jquery.data( elem );

                    if ( elem.nodetype === 1 && !jquery._data( elem, "parsedattrs" ) ) {
                        attrs = elem.attributes;
                        for ( ; i < attrs.length; i++ ) {
                            name = attrs[i].name;

                            if ( name.indexof("data-") === 0 ) {
                                name = jquery.camelcase( name.slice(5) );

                                dataattr( elem, name, data[ name ] );
                            }
                        }
                        jquery._data( elem, "parsedattrs", true );
                    }
                }

                return data;
            }

            // sets multiple values
            if ( typeof key === "object" ) {
                return this.each(function() {
                    jquery.data( this, key );
                });
            }

            return arguments.length > 1 ?

                // sets one value
                this.each(function() {
                    jquery.data( this, key, value );
                }) :

                // gets one value
                // try to fetch any internally stored data first
                elem ? dataattr( elem, key, jquery.data( elem, key ) ) : null;
        },

        removedata: function( key ) {
            return this.each(function() {
                jquery.removedata( this, key );
            });
        }
    });

    function dataattr( elem, key, data ) {
        // if nothing was found internally, try to fetch any
        // data from the html5 data-* attribute
        if ( data === undefined && elem.nodetype === 1 ) {

            var name = "data-" + key.replace( rmultidash, "-$1" ).tolowercase();

            data = elem.getattribute( name );

            if ( typeof data === "string" ) {
                try {
                    data = data === "true" ? true :
                            data === "false" ? false :
                            data === "null" ? null :
                        // only convert to a number if it doesn't change the string
                            +data + "" === data ? +data :
                        rbrace.test( data ) ? jquery.parsejson( data ) :
                            data;
                } catch( e ) {}

                // make sure we set the data so it isn't changed later
                jquery.data( elem, key, data );

            } else {
                data = undefined;
            }
        }

        return data;
    }

// checks a cache object for emptiness
    function isemptydataobject( obj ) {
        var name;
        for ( name in obj ) {

            // if the public data object is empty, the private is still empty
            if ( name === "data" && jquery.isemptyobject( obj[name] ) ) {
                continue;
            }
            if ( name !== "tojson" ) {
                return false;
            }
        }

        return true;
    }
    jquery.extend({
        queue: function( elem, type, data ) {
            var queue;

            if ( elem ) {
                type = ( type || "fx" ) + "queue";
                queue = jquery._data( elem, type );

                // speed up dequeue by getting out quickly if this is just a lookup
                if ( data ) {
                    if ( !queue || jquery.isarray(data) ) {
                        queue = jquery._data( elem, type, jquery.makearray(data) );
                    } else {
                        queue.push( data );
                    }
                }
                return queue || [];
            }
        },

        dequeue: function( elem, type ) {
            type = type || "fx";

            var queue = jquery.queue( elem, type ),
                startlength = queue.length,
                fn = queue.shift(),
                hooks = jquery._queuehooks( elem, type ),
                next = function() {
                    jquery.dequeue( elem, type );
                };

            // if the fx queue is dequeued, always remove the progress sentinel
            if ( fn === "inprogress" ) {
                fn = queue.shift();
                startlength--;
            }

            if ( fn ) {

                // add a progress sentinel to prevent the fx queue from being
                // automatically dequeued
                if ( type === "fx" ) {
                    queue.unshift( "inprogress" );
                }

                // clear up the last queue stop function
                delete hooks.stop;
                fn.call( elem, next, hooks );
            }

            if ( !startlength && hooks ) {
                hooks.empty.fire();
            }
        },

        // not intended for public consumption - generates a queuehooks object, or returns the current one
        _queuehooks: function( elem, type ) {
            var key = type + "queuehooks";
            return jquery._data( elem, key ) || jquery._data( elem, key, {
                empty: jquery.callbacks("once memory").add(function() {
                    jquery._removedata( elem, type + "queue" );
                    jquery._removedata( elem, key );
                })
            });
        }
    });

    jquery.fn.extend({
        queue: function( type, data ) {
            var setter = 2;

            if ( typeof type !== "string" ) {
                data = type;
                type = "fx";
                setter--;
            }

            if ( arguments.length < setter ) {
                return jquery.queue( this[0], type );
            }

            return data === undefined ?
                this :
                this.each(function() {
                    var queue = jquery.queue( this, type, data );

                    // ensure a hooks for this queue
                    jquery._queuehooks( this, type );

                    if ( type === "fx" && queue[0] !== "inprogress" ) {
                        jquery.dequeue( this, type );
                    }
                });
        },
        dequeue: function( type ) {
            return this.each(function() {
                jquery.dequeue( this, type );
            });
        },
        // based off of the plugin by clint helfers, with permission.
        // http://blindsignals.com/index.php/2009/07/jquery-delay/
        delay: function( time, type ) {
            time = jquery.fx ? jquery.fx.speeds[ time ] || time : time;
            type = type || "fx";

            return this.queue( type, function( next, hooks ) {
                var timeout = settimeout( next, time );
                hooks.stop = function() {
                    cleartimeout( timeout );
                };
            });
        },
        clearqueue: function( type ) {
            return this.queue( type || "fx", [] );
        },
        // get a promise resolved when queues of a certain type
        // are emptied (fx is the type by default)
        promise: function( type, obj ) {
            var tmp,
                count = 1,
                defer = jquery.deferred(),
                elements = this,
                i = this.length,
                resolve = function() {
                    if ( !( --count ) ) {
                        defer.resolvewith( elements, [ elements ] );
                    }
                };

            if ( typeof type !== "string" ) {
                obj = type;
                type = undefined;
            }
            type = type || "fx";

            while( i-- ) {
                tmp = jquery._data( elements[ i ], type + "queuehooks" );
                if ( tmp && tmp.empty ) {
                    count++;
                    tmp.empty.add( resolve );
                }
            }
            resolve();
            return defer.promise( obj );
        }
    });
    var nodehook, boolhook,
        rclass = /[\t\r\n\f]/g,
        rreturn = /\r/g,
        rfocusable = /^(?:input|select|textarea|button|object)$/i,
        rclickable = /^(?:a|area)$/i,
        rusedefault = /^(?:checked|selected)$/i,
        getsetattribute = jquery.support.getsetattribute,
        getsetinput = jquery.support.input;

    jquery.fn.extend({
        attr: function( name, value ) {
            return jquery.access( this, jquery.attr, name, value, arguments.length > 1 );
        },

        removeattr: function( name ) {
            return this.each(function() {
                jquery.removeattr( this, name );
            });
        },

        prop: function( name, value ) {
            return jquery.access( this, jquery.prop, name, value, arguments.length > 1 );
        },

        removeprop: function( name ) {
            name = jquery.propfix[ name ] || name;
            return this.each(function() {
                // try/catch handles cases where ie balks (such as removing a property on window)
                try {
                    this[ name ] = undefined;
                    delete this[ name ];
                } catch( e ) {}
            });
        },

        addclass: function( value ) {
            var classes, elem, cur, clazz, j,
                i = 0,
                len = this.length,
                proceed = typeof value === "string" && value;

            if ( jquery.isfunction( value ) ) {
                return this.each(function( j ) {
                    jquery( this ).addclass( value.call( this, j, this.classname ) );
                });
            }

            if ( proceed ) {
                // the disjunction here is for better compressibility (see removeclass)
                classes = ( value || "" ).match( core_rnotwhite ) || [];

                for ( ; i < len; i++ ) {
                    elem = this[ i ];
                    cur = elem.nodetype === 1 && ( elem.classname ?
                        ( " " + elem.classname + " " ).replace( rclass, " " ) :
                        " "
                        );

                    if ( cur ) {
                        j = 0;
                        while ( (clazz = classes[j++]) ) {
                            if ( cur.indexof( " " + clazz + " " ) < 0 ) {
                                cur += clazz + " ";
                            }
                        }
                        elem.classname = jquery.trim( cur );

                    }
                }
            }

            return this;
        },

        removeclass: function( value ) {
            var classes, elem, cur, clazz, j,
                i = 0,
                len = this.length,
                proceed = arguments.length === 0 || typeof value === "string" && value;

            if ( jquery.isfunction( value ) ) {
                return this.each(function( j ) {
                    jquery( this ).removeclass( value.call( this, j, this.classname ) );
                });
            }
            if ( proceed ) {
                classes = ( value || "" ).match( core_rnotwhite ) || [];

                for ( ; i < len; i++ ) {
                    elem = this[ i ];
                    // this expression is here for better compressibility (see addclass)
                    cur = elem.nodetype === 1 && ( elem.classname ?
                        ( " " + elem.classname + " " ).replace( rclass, " " ) :
                        ""
                        );

                    if ( cur ) {
                        j = 0;
                        while ( (clazz = classes[j++]) ) {
                            // remove *all* instances
                            while ( cur.indexof( " " + clazz + " " ) >= 0 ) {
                                cur = cur.replace( " " + clazz + " ", " " );
                            }
                        }
                        elem.classname = value ? jquery.trim( cur ) : "";
                    }
                }
            }

            return this;
        },

        toggleclass: function( value, stateval ) {
            var type = typeof value;

            if ( typeof stateval === "boolean" && type === "string" ) {
                return stateval ? this.addclass( value ) : this.removeclass( value );
            }

            if ( jquery.isfunction( value ) ) {
                return this.each(function( i ) {
                    jquery( this ).toggleclass( value.call(this, i, this.classname, stateval), stateval );
                });
            }

            return this.each(function() {
                if ( type === "string" ) {
                    // toggle individual class names
                    var classname,
                        i = 0,
                        self = jquery( this ),
                        classnames = value.match( core_rnotwhite ) || [];

                    while ( (classname = classnames[ i++ ]) ) {
                        // check each classname given, space separated list
                        if ( self.hasclass( classname ) ) {
                            self.removeclass( classname );
                        } else {
                            self.addclass( classname );
                        }
                    }

                    // toggle whole class name
                } else if ( type === core_strundefined || type === "boolean" ) {
                    if ( this.classname ) {
                        // store classname if set
                        jquery._data( this, "__classname__", this.classname );
                    }

                    // if the element has a class name or if we're passed "false",
                    // then remove the whole classname (if there was one, the above saved it).
                    // otherwise bring back whatever was previously saved (if anything),
                    // falling back to the empty string if nothing was stored.
                    this.classname = this.classname || value === false ? "" : jquery._data( this, "__classname__" ) || "";
                }
            });
        },

        hasclass: function( selector ) {
            var classname = " " + selector + " ",
                i = 0,
                l = this.length;
            for ( ; i < l; i++ ) {
                if ( this[i].nodetype === 1 && (" " + this[i].classname + " ").replace(rclass, " ").indexof( classname ) >= 0 ) {
                    return true;
                }
            }

            return false;
        },

        val: function( value ) {
            var ret, hooks, isfunction,
                elem = this[0];

            if ( !arguments.length ) {
                if ( elem ) {
                    hooks = jquery.valhooks[ elem.type ] || jquery.valhooks[ elem.nodename.tolowercase() ];

                    if ( hooks && "get" in hooks && (ret = hooks.get( elem, "value" )) !== undefined ) {
                        return ret;
                    }

                    ret = elem.value;

                    return typeof ret === "string" ?
                        // handle most common string cases
                        ret.replace(rreturn, "") :
                        // handle cases where value is null/undef or number
                            ret == null ? "" : ret;
                }

                return;
            }

            isfunction = jquery.isfunction( value );

            return this.each(function( i ) {
                var val;

                if ( this.nodetype !== 1 ) {
                    return;
                }

                if ( isfunction ) {
                    val = value.call( this, i, jquery( this ).val() );
                } else {
                    val = value;
                }

                // treat null/undefined as ""; convert numbers to string
                if ( val == null ) {
                    val = "";
                } else if ( typeof val === "number" ) {
                    val += "";
                } else if ( jquery.isarray( val ) ) {
                    val = jquery.map(val, function ( value ) {
                        return value == null ? "" : value + "";
                    });
                }

                hooks = jquery.valhooks[ this.type ] || jquery.valhooks[ this.nodename.tolowercase() ];

                // if set returns undefined, fall back to normal setting
                if ( !hooks || !("set" in hooks) || hooks.set( this, val, "value" ) === undefined ) {
                    this.value = val;
                }
            });
        }
    });

    jquery.extend({
        valhooks: {
            option: {
                get: function( elem ) {
                    // use proper attribute retrieval(#6932, #12072)
                    var val = jquery.find.attr( elem, "value" );
                    return val != null ?
                        val :
                        elem.text;
                }
            },
            select: {
                get: function( elem ) {
                    var value, option,
                        options = elem.options,
                        index = elem.selectedindex,
                        one = elem.type === "select-one" || index < 0,
                        values = one ? null : [],
                        max = one ? index + 1 : options.length,
                        i = index < 0 ?
                            max :
                            one ? index : 0;

                    // loop through all the selected options
                    for ( ; i < max; i++ ) {
                        option = options[ i ];

                        // oldie doesn't update selected after form reset (#2551)
                        if ( ( option.selected || i === index ) &&
                            // don't return options that are disabled or in a disabled optgroup
                            ( jquery.support.optdisabled ? !option.disabled : option.getattribute("disabled") === null ) &&
                            ( !option.parentnode.disabled || !jquery.nodename( option.parentnode, "optgroup" ) ) ) {

                            // get the specific value for the option
                            value = jquery( option ).val();

                            // we don't need an array for one selects
                            if ( one ) {
                                return value;
                            }

                            // multi-selects return an array
                            values.push( value );
                        }
                    }

                    return values;
                },

                set: function( elem, value ) {
                    var optionset, option,
                        options = elem.options,
                        values = jquery.makearray( value ),
                        i = options.length;

                    while ( i-- ) {
                        option = options[ i ];
                        if ( (option.selected = jquery.inarray( jquery(option).val(), values ) >= 0) ) {
                            optionset = true;
                        }
                    }

                    // force browsers to behave consistently when non-matching value is set
                    if ( !optionset ) {
                        elem.selectedindex = -1;
                    }
                    return values;
                }
            }
        },

        attr: function( elem, name, value ) {
            var hooks, ret,
                ntype = elem.nodetype;

            // don't get/set attributes on text, comment and attribute nodes
            if ( !elem || ntype === 3 || ntype === 8 || ntype === 2 ) {
                return;
            }

            // fallback to prop when attributes are not supported
            if ( typeof elem.getattribute === core_strundefined ) {
                return jquery.prop( elem, name, value );
            }

            // all attributes are lowercase
            // grab necessary hook if one is defined
            if ( ntype !== 1 || !jquery.isxmldoc( elem ) ) {
                name = name.tolowercase();
                hooks = jquery.attrhooks[ name ] ||
                    ( jquery.expr.match.bool.test( name ) ? boolhook : nodehook );
            }

            if ( value !== undefined ) {

                if ( value === null ) {
                    jquery.removeattr( elem, name );

                } else if ( hooks && "set" in hooks && (ret = hooks.set( elem, value, name )) !== undefined ) {
                    return ret;

                } else {
                    elem.setattribute( name, value + "" );
                    return value;
                }

            } else if ( hooks && "get" in hooks && (ret = hooks.get( elem, name )) !== null ) {
                return ret;

            } else {
                ret = jquery.find.attr( elem, name );

                // non-existent attributes return null, we normalize to undefined
                return ret == null ?
                    undefined :
                    ret;
            }
        },

        removeattr: function( elem, value ) {
            var name, propname,
                i = 0,
                attrnames = value && value.match( core_rnotwhite );

            if ( attrnames && elem.nodetype === 1 ) {
                while ( (name = attrnames[i++]) ) {
                    propname = jquery.propfix[ name ] || name;

                    // boolean attributes get special treatment (#10870)
                    if ( jquery.expr.match.bool.test( name ) ) {
                        // set corresponding property to false
                        if ( getsetinput && getsetattribute || !rusedefault.test( name ) ) {
                            elem[ propname ] = false;
                            // support: ie<9
                            // also clear defaultchecked/defaultselected (if appropriate)
                        } else {
                            elem[ jquery.camelcase( "default-" + name ) ] =
                                elem[ propname ] = false;
                        }

                        // see #9699 for explanation of this approach (setting first, then removal)
                    } else {
                        jquery.attr( elem, name, "" );
                    }

                    elem.removeattribute( getsetattribute ? name : propname );
                }
            }
        },

        attrhooks: {
            type: {
                set: function( elem, value ) {
                    if ( !jquery.support.radiovalue && value === "radio" && jquery.nodename(elem, "input") ) {
                        // setting the type on a radio button after the value resets the value in ie6-9
                        // reset value to default in case type is set after value during creation
                        var val = elem.value;
                        elem.setattribute( "type", value );
                        if ( val ) {
                            elem.value = val;
                        }
                        return value;
                    }
                }
            }
        },

        propfix: {
            "for": "htmlfor",
            "class": "classname"
        },

        prop: function( elem, name, value ) {
            var ret, hooks, notxml,
                ntype = elem.nodetype;

            // don't get/set properties on text, comment and attribute nodes
            if ( !elem || ntype === 3 || ntype === 8 || ntype === 2 ) {
                return;
            }

            notxml = ntype !== 1 || !jquery.isxmldoc( elem );

            if ( notxml ) {
                // fix name and attach hooks
                name = jquery.propfix[ name ] || name;
                hooks = jquery.prophooks[ name ];
            }

            if ( value !== undefined ) {
                return hooks && "set" in hooks && (ret = hooks.set( elem, value, name )) !== undefined ?
                    ret :
                    ( elem[ name ] = value );

            } else {
                return hooks && "get" in hooks && (ret = hooks.get( elem, name )) !== null ?
                    ret :
                    elem[ name ];
            }
        },

        prophooks: {
            tabindex: {
                get: function( elem ) {
                    // elem.tabindex doesn't always return the correct value when it hasn't been explicitly set
                    // http://fluidproject.org/blog/2008/01/09/getting-setting-and-removing-tabindex-values-with-javascript/
                    // use proper attribute retrieval(#12072)
                    var tabindex = jquery.find.attr( elem, "tabindex" );

                    return tabindex ?
                        parseint( tabindex, 10 ) :
                            rfocusable.test( elem.nodename ) || rclickable.test( elem.nodename ) && elem.href ?
                        0 :
                        -1;
                }
            }
        }
    });

// hooks for boolean attributes
    boolhook = {
        set: function( elem, value, name ) {
            if ( value === false ) {
                // remove boolean attributes when set to false
                jquery.removeattr( elem, name );
            } else if ( getsetinput && getsetattribute || !rusedefault.test( name ) ) {
                // ie<8 needs the *property* name
                elem.setattribute( !getsetattribute && jquery.propfix[ name ] || name, name );

                // use defaultchecked and defaultselected for oldie
            } else {
                elem[ jquery.camelcase( "default-" + name ) ] = elem[ name ] = true;
            }

            return name;
        }
    };
    jquery.each( jquery.expr.match.bool.source.match( /\w+/g ), function( i, name ) {
        var getter = jquery.expr.attrhandle[ name ] || jquery.find.attr;

        jquery.expr.attrhandle[ name ] = getsetinput && getsetattribute || !rusedefault.test( name ) ?
            function( elem, name, isxml ) {
                var fn = jquery.expr.attrhandle[ name ],
                    ret = isxml ?
                        undefined :
                        /* jshint eqeqeq: false */
                            (jquery.expr.attrhandle[ name ] = undefined) !=
                        getter( elem, name, isxml ) ?

                        name.tolowercase() :
                        null;
                jquery.expr.attrhandle[ name ] = fn;
                return ret;
            } :
            function( elem, name, isxml ) {
                return isxml ?
                    undefined :
                    elem[ jquery.camelcase( "default-" + name ) ] ?
                        name.tolowercase() :
                        null;
            };
    });

// fix oldie attroperties
    if ( !getsetinput || !getsetattribute ) {
        jquery.attrhooks.value = {
            set: function( elem, value, name ) {
                if ( jquery.nodename( elem, "input" ) ) {
                    // does not return so that setattribute is also used
                    elem.defaultvalue = value;
                } else {
                    // use nodehook if defined (#1954); otherwise setattribute is fine
                    return nodehook && nodehook.set( elem, value, name );
                }
            }
        };
    }

// ie6/7 do not support getting/setting some attributes with get/setattribute
    if ( !getsetattribute ) {

        // use this for any attribute in ie6/7
        // this fixes almost every ie6/7 issue
        nodehook = {
            set: function( elem, value, name ) {
                // set the existing or create a new attribute node
                var ret = elem.getattributenode( name );
                if ( !ret ) {
                    elem.setattributenode(
                        (ret = elem.ownerdocument.createattribute( name ))
                    );
                }

                ret.value = value += "";

                // break association with cloned elements by also using setattribute (#9646)
                return name === "value" || value === elem.getattribute( name ) ?
                    value :
                    undefined;
            }
        };
        jquery.expr.attrhandle.id = jquery.expr.attrhandle.name = jquery.expr.attrhandle.coords =
            // some attributes are constructed with empty-string values when not defined
            function( elem, name, isxml ) {
                var ret;
                return isxml ?
                    undefined :
                        (ret = elem.getattributenode( name )) && ret.value !== "" ?
                    ret.value :
                    null;
            };
        jquery.valhooks.button = {
            get: function( elem, name ) {
                var ret = elem.getattributenode( name );
                return ret && ret.specified ?
                    ret.value :
                    undefined;
            },
            set: nodehook.set
        };

        // set contenteditable to false on removals(#10429)
        // setting to empty string throws an error as an invalid value
        jquery.attrhooks.contenteditable = {
            set: function( elem, value, name ) {
                nodehook.set( elem, value === "" ? false : value, name );
            }
        };

        // set width and height to auto instead of 0 on empty string( bug #8150 )
        // this is for removals
        jquery.each([ "width", "height" ], function( i, name ) {
            jquery.attrhooks[ name ] = {
                set: function( elem, value ) {
                    if ( value === "" ) {
                        elem.setattribute( name, "auto" );
                        return value;
                    }
                }
            };
        });
    }


// some attributes require a special call on ie
// http://msdn.microsoft.com/en-us/library/ms536429%28vs.85%29.aspx
    if ( !jquery.support.hrefnormalized ) {
        // href/src property should get the full normalized url (#10299/#12915)
        jquery.each([ "href", "src" ], function( i, name ) {
            jquery.prophooks[ name ] = {
                get: function( elem ) {
                    return elem.getattribute( name, 4 );
                }
            };
        });
    }

    if ( !jquery.support.style ) {
        jquery.attrhooks.style = {
            get: function( elem ) {
                // return undefined in the case of empty string
                // note: ie uppercases css property names, but if we were to .tolowercase()
                // .csstext, that would destroy case senstitivity in url's, like in "background"
                return elem.style.csstext || undefined;
            },
            set: function( elem, value ) {
                return ( elem.style.csstext = value + "" );
            }
        };
    }

// safari mis-reports the default selected property of an option
// accessing the parent's selectedindex property fixes it
    if ( !jquery.support.optselected ) {
        jquery.prophooks.selected = {
            get: function( elem ) {
                var parent = elem.parentnode;

                if ( parent ) {
                    parent.selectedindex;

                    // make sure that it also works with optgroups, see #5701
                    if ( parent.parentnode ) {
                        parent.parentnode.selectedindex;
                    }
                }
                return null;
            }
        };
    }

    jquery.each([
        "tabindex",
        "readonly",
        "maxlength",
        "cellspacing",
        "cellpadding",
        "rowspan",
        "colspan",
        "usemap",
        "frameborder",
        "contenteditable"
    ], function() {
        jquery.propfix[ this.tolowercase() ] = this;
    });

// ie6/7 call enctype encoding
    if ( !jquery.support.enctype ) {
        jquery.propfix.enctype = "encoding";
    }

// radios and checkboxes getter/setter
    jquery.each([ "radio", "checkbox" ], function() {
        jquery.valhooks[ this ] = {
            set: function( elem, value ) {
                if ( jquery.isarray( value ) ) {
                    return ( elem.checked = jquery.inarray( jquery(elem).val(), value ) >= 0 );
                }
            }
        };
        if ( !jquery.support.checkon ) {
            jquery.valhooks[ this ].get = function( elem ) {
                // support: webkit
                // "" is returned instead of "on" if a value isn't specified
                return elem.getattribute("value") === null ? "on" : elem.value;
            };
        }
    });
    var rformelems = /^(?:input|select|textarea)$/i,
        rkeyevent = /^key/,
        rmouseevent = /^(?:mouse|contextmenu)|click/,
        rfocusmorph = /^(?:focusinfocus|focusoutblur)$/,
        rtypenamespace = /^([^.]*)(?:\.(.+)|)$/;

    function returntrue() {
        return true;
    }

    function returnfalse() {
        return false;
    }

    function safeactiveelement() {
        try {
            return document.activeelement;
        } catch ( err ) { }
    }

    /*
     * helper functions for managing events -- not part of the public interface.
     * props to dean edwards' addevent library for many of the ideas.
     */
    jquery.event = {

        global: {},

        add: function( elem, types, handler, data, selector ) {
            var tmp, events, t, handleobjin,
                special, eventhandle, handleobj,
                handlers, type, namespaces, origtype,
                elemdata = jquery._data( elem );

            // don't attach events to nodata or text/comment nodes (but allow plain objects)
            if ( !elemdata ) {
                return;
            }

            // caller can pass in an object of custom data in lieu of the handler
            if ( handler.handler ) {
                handleobjin = handler;
                handler = handleobjin.handler;
                selector = handleobjin.selector;
            }

            // make sure that the handler has a unique id, used to find/remove it later
            if ( !handler.guid ) {
                handler.guid = jquery.guid++;
            }

            // init the element's event structure and main handler, if this is the first
            if ( !(events = elemdata.events) ) {
                events = elemdata.events = {};
            }
            if ( !(eventhandle = elemdata.handle) ) {
                eventhandle = elemdata.handle = function( e ) {
                    // discard the second event of a jquery.event.trigger() and
                    // when an event is called after a page has unloaded
                    return typeof jquery !== core_strundefined && (!e || jquery.event.triggered !== e.type) ?
                        jquery.event.dispatch.apply( eventhandle.elem, arguments ) :
                        undefined;
                };
                // add elem as a property of the handle fn to prevent a memory leak with ie non-native events
                eventhandle.elem = elem;
            }

            // handle multiple events separated by a space
            types = ( types || "" ).match( core_rnotwhite ) || [""];
            t = types.length;
            while ( t-- ) {
                tmp = rtypenamespace.exec( types[t] ) || [];
                type = origtype = tmp[1];
                namespaces = ( tmp[2] || "" ).split( "." ).sort();

                // there *must* be a type, no attaching namespace-only handlers
                if ( !type ) {
                    continue;
                }

                // if event changes its type, use the special event handlers for the changed type
                special = jquery.event.special[ type ] || {};

                // if selector defined, determine special event api type, otherwise given type
                type = ( selector ? special.delegatetype : special.bindtype ) || type;

                // update special based on newly reset type
                special = jquery.event.special[ type ] || {};

                // handleobj is passed to all event handlers
                handleobj = jquery.extend({
                    type: type,
                    origtype: origtype,
                    data: data,
                    handler: handler,
                    guid: handler.guid,
                    selector: selector,
                    needscontext: selector && jquery.expr.match.needscontext.test( selector ),
                    namespace: namespaces.join(".")
                }, handleobjin );

                // init the event handler queue if we're the first
                if ( !(handlers = events[ type ]) ) {
                    handlers = events[ type ] = [];
                    handlers.delegatecount = 0;

                    // only use addeventlistener/attachevent if the special events handler returns false
                    if ( !special.setup || special.setup.call( elem, data, namespaces, eventhandle ) === false ) {
                        // bind the global event handler to the element
                        if ( elem.addeventlistener ) {
                            elem.addeventlistener( type, eventhandle, false );

                        } else if ( elem.attachevent ) {
                            elem.attachevent( "on" + type, eventhandle );
                        }
                    }
                }

                if ( special.add ) {
                    special.add.call( elem, handleobj );

                    if ( !handleobj.handler.guid ) {
                        handleobj.handler.guid = handler.guid;
                    }
                }

                // add to the element's handler list, delegates in front
                if ( selector ) {
                    handlers.splice( handlers.delegatecount++, 0, handleobj );
                } else {
                    handlers.push( handleobj );
                }

                // keep track of which events have ever been used, for event optimization
                jquery.event.global[ type ] = true;
            }

            // nullify elem to prevent memory leaks in ie
            elem = null;
        },

        // detach an event or set of events from an element
        remove: function( elem, types, handler, selector, mappedtypes ) {
            var j, handleobj, tmp,
                origcount, t, events,
                special, handlers, type,
                namespaces, origtype,
                elemdata = jquery.hasdata( elem ) && jquery._data( elem );

            if ( !elemdata || !(events = elemdata.events) ) {
                return;
            }

            // once for each type.namespace in types; type may be omitted
            types = ( types || "" ).match( core_rnotwhite ) || [""];
            t = types.length;
            while ( t-- ) {
                tmp = rtypenamespace.exec( types[t] ) || [];
                type = origtype = tmp[1];
                namespaces = ( tmp[2] || "" ).split( "." ).sort();

                // unbind all events (on this namespace, if provided) for the element
                if ( !type ) {
                    for ( type in events ) {
                        jquery.event.remove( elem, type + types[ t ], handler, selector, true );
                    }
                    continue;
                }

                special = jquery.event.special[ type ] || {};
                type = ( selector ? special.delegatetype : special.bindtype ) || type;
                handlers = events[ type ] || [];
                tmp = tmp[2] && new regexp( "(^|\\.)" + namespaces.join("\\.(?:.*\\.|)") + "(\\.|$)" );

                // remove matching events
                origcount = j = handlers.length;
                while ( j-- ) {
                    handleobj = handlers[ j ];

                    if ( ( mappedtypes || origtype === handleobj.origtype ) &&
                        ( !handler || handler.guid === handleobj.guid ) &&
                        ( !tmp || tmp.test( handleobj.namespace ) ) &&
                        ( !selector || selector === handleobj.selector || selector === "**" && handleobj.selector ) ) {
                        handlers.splice( j, 1 );

                        if ( handleobj.selector ) {
                            handlers.delegatecount--;
                        }
                        if ( special.remove ) {
                            special.remove.call( elem, handleobj );
                        }
                    }
                }

                // remove generic event handler if we removed something and no more handlers exist
                // (avoids potential for endless recursion during removal of special event handlers)
                if ( origcount && !handlers.length ) {
                    if ( !special.teardown || special.teardown.call( elem, namespaces, elemdata.handle ) === false ) {
                        jquery.removeevent( elem, type, elemdata.handle );
                    }

                    delete events[ type ];
                }
            }

            // remove the expando if it's no longer used
            if ( jquery.isemptyobject( events ) ) {
                delete elemdata.handle;

                // removedata also checks for emptiness and clears the expando if empty
                // so use it instead of delete
                jquery._removedata( elem, "events" );
            }
        },

        trigger: function( event, data, elem, onlyhandlers ) {
            var handle, ontype, cur,
                bubbletype, special, tmp, i,
                eventpath = [ elem || document ],
                type = core_hasown.call( event, "type" ) ? event.type : event,
                namespaces = core_hasown.call( event, "namespace" ) ? event.namespace.split(".") : [];

            cur = tmp = elem = elem || document;

            // don't do events on text and comment nodes
            if ( elem.nodetype === 3 || elem.nodetype === 8 ) {
                return;
            }

            // focus/blur morphs to focusin/out; ensure we're not firing them right now
            if ( rfocusmorph.test( type + jquery.event.triggered ) ) {
                return;
            }

            if ( type.indexof(".") >= 0 ) {
                // namespaced trigger; create a regexp to match event type in handle()
                namespaces = type.split(".");
                type = namespaces.shift();
                namespaces.sort();
            }
            ontype = type.indexof(":") < 0 && "on" + type;

            // caller can pass in a jquery.event object, object, or just an event type string
            event = event[ jquery.expando ] ?
                event :
                new jquery.event( type, typeof event === "object" && event );

            // trigger bitmask: & 1 for native handlers; & 2 for jquery (always true)
            event.istrigger = onlyhandlers ? 2 : 3;
            event.namespace = namespaces.join(".");
            event.namespace_re = event.namespace ?
                new regexp( "(^|\\.)" + namespaces.join("\\.(?:.*\\.|)") + "(\\.|$)" ) :
                null;

            // clean up the event in case it is being reused
            event.result = undefined;
            if ( !event.target ) {
                event.target = elem;
            }

            // clone any incoming data and prepend the event, creating the handler arg list
            data = data == null ?
                [ event ] :
                jquery.makearray( data, [ event ] );

            // allow special events to draw outside the lines
            special = jquery.event.special[ type ] || {};
            if ( !onlyhandlers && special.trigger && special.trigger.apply( elem, data ) === false ) {
                return;
            }

            // determine event propagation path in advance, per w3c events spec (#9951)
            // bubble up to document, then to window; watch for a global ownerdocument var (#9724)
            if ( !onlyhandlers && !special.nobubble && !jquery.iswindow( elem ) ) {

                bubbletype = special.delegatetype || type;
                if ( !rfocusmorph.test( bubbletype + type ) ) {
                    cur = cur.parentnode;
                }
                for ( ; cur; cur = cur.parentnode ) {
                    eventpath.push( cur );
                    tmp = cur;
                }

                // only add window if we got to document (e.g., not plain obj or detached dom)
                if ( tmp === (elem.ownerdocument || document) ) {
                    eventpath.push( tmp.defaultview || tmp.parentwindow || window );
                }
            }

            // fire handlers on the event path
            i = 0;
            while ( (cur = eventpath[i++]) && !event.ispropagationstopped() ) {

                event.type = i > 1 ?
                    bubbletype :
                    special.bindtype || type;

                // jquery handler
                handle = ( jquery._data( cur, "events" ) || {} )[ event.type ] && jquery._data( cur, "handle" );
                if ( handle ) {
                    handle.apply( cur, data );
                }

                // native handler
                handle = ontype && cur[ ontype ];
                if ( handle && jquery.acceptdata( cur ) && handle.apply && handle.apply( cur, data ) === false ) {
                    event.preventdefault();
                }
            }
            event.type = type;

            // if nobody prevented the default action, do it now
            if ( !onlyhandlers && !event.isdefaultprevented() ) {

                if ( (!special._default || special._default.apply( eventpath.pop(), data ) === false) &&
                    jquery.acceptdata( elem ) ) {

                    // call a native dom method on the target with the same name name as the event.
                    // can't use an .isfunction() check here because ie6/7 fails that test.
                    // don't do default actions on window, that's where global variables be (#6170)
                    if ( ontype && elem[ type ] && !jquery.iswindow( elem ) ) {

                        // don't re-trigger an onfoo event when we call its foo() method
                        tmp = elem[ ontype ];

                        if ( tmp ) {
                            elem[ ontype ] = null;
                        }

                        // prevent re-triggering of the same event, since we already bubbled it above
                        jquery.event.triggered = type;
                        try {
                            elem[ type ]();
                        } catch ( e ) {
                            // ie<9 dies on focus/blur to hidden element (#1486,#12518)
                            // only reproducible on winxp ie8 native, not ie9 in ie8 mode
                        }
                        jquery.event.triggered = undefined;

                        if ( tmp ) {
                            elem[ ontype ] = tmp;
                        }
                    }
                }
            }

            return event.result;
        },

        dispatch: function( event ) {

            // make a writable jquery.event from the native event object
            event = jquery.event.fix( event );

            var i, ret, handleobj, matched, j,
                handlerqueue = [],
                args = core_slice.call( arguments ),
                handlers = ( jquery._data( this, "events" ) || {} )[ event.type ] || [],
                special = jquery.event.special[ event.type ] || {};

            // use the fix-ed jquery.event rather than the (read-only) native event
            args[0] = event;
            event.delegatetarget = this;

            // call the predispatch hook for the mapped type, and let it bail if desired
            if ( special.predispatch && special.predispatch.call( this, event ) === false ) {
                return;
            }

            // determine handlers
            handlerqueue = jquery.event.handlers.call( this, event, handlers );

            // run delegates first; they may want to stop propagation beneath us
            i = 0;
            while ( (matched = handlerqueue[ i++ ]) && !event.ispropagationstopped() ) {
                event.currenttarget = matched.elem;

                j = 0;
                while ( (handleobj = matched.handlers[ j++ ]) && !event.isimmediatepropagationstopped() ) {

                    // triggered event must either 1) have no namespace, or
                    // 2) have namespace(s) a subset or equal to those in the bound event (both can have no namespace).
                    if ( !event.namespace_re || event.namespace_re.test( handleobj.namespace ) ) {

                        event.handleobj = handleobj;
                        event.data = handleobj.data;

                        ret = ( (jquery.event.special[ handleobj.origtype ] || {}).handle || handleobj.handler )
                            .apply( matched.elem, args );

                        if ( ret !== undefined ) {
                            if ( (event.result = ret) === false ) {
                                event.preventdefault();
                                event.stoppropagation();
                            }
                        }
                    }
                }
            }

            // call the postdispatch hook for the mapped type
            if ( special.postdispatch ) {
                special.postdispatch.call( this, event );
            }

            return event.result;
        },

        handlers: function( event, handlers ) {
            var sel, handleobj, matches, i,
                handlerqueue = [],
                delegatecount = handlers.delegatecount,
                cur = event.target;

            // find delegate handlers
            // black-hole svg <use> instance trees (#13180)
            // avoid non-left-click bubbling in firefox (#3861)
            if ( delegatecount && cur.nodetype && (!event.button || event.type !== "click") ) {

                /* jshint eqeqeq: false */
                for ( ; cur != this; cur = cur.parentnode || this ) {
                    /* jshint eqeqeq: true */

                    // don't check non-elements (#13208)
                    // don't process clicks on disabled elements (#6911, #8165, #11382, #11764)
                    if ( cur.nodetype === 1 && (cur.disabled !== true || event.type !== "click") ) {
                        matches = [];
                        for ( i = 0; i < delegatecount; i++ ) {
                            handleobj = handlers[ i ];

                            // don't conflict with object.prototype properties (#13203)
                            sel = handleobj.selector + " ";

                            if ( matches[ sel ] === undefined ) {
                                matches[ sel ] = handleobj.needscontext ?
                                    jquery( sel, this ).index( cur ) >= 0 :
                                    jquery.find( sel, this, null, [ cur ] ).length;
                            }
                            if ( matches[ sel ] ) {
                                matches.push( handleobj );
                            }
                        }
                        if ( matches.length ) {
                            handlerqueue.push({ elem: cur, handlers: matches });
                        }
                    }
                }
            }

            // add the remaining (directly-bound) handlers
            if ( delegatecount < handlers.length ) {
                handlerqueue.push({ elem: this, handlers: handlers.slice( delegatecount ) });
            }

            return handlerqueue;
        },

        fix: function( event ) {
            if ( event[ jquery.expando ] ) {
                return event;
            }

            // create a writable copy of the event object and normalize some properties
            var i, prop, copy,
                type = event.type,
                originalevent = event,
                fixhook = this.fixhooks[ type ];

            if ( !fixhook ) {
                this.fixhooks[ type ] = fixhook =
                    rmouseevent.test( type ) ? this.mousehooks :
                        rkeyevent.test( type ) ? this.keyhooks :
                        {};
            }
            copy = fixhook.props ? this.props.concat( fixhook.props ) : this.props;

            event = new jquery.event( originalevent );

            i = copy.length;
            while ( i-- ) {
                prop = copy[ i ];
                event[ prop ] = originalevent[ prop ];
            }

            // support: ie<9
            // fix target property (#1925)
            if ( !event.target ) {
                event.target = originalevent.srcelement || document;
            }

            // support: chrome 23+, safari?
            // target should not be a text node (#504, #13143)
            if ( event.target.nodetype === 3 ) {
                event.target = event.target.parentnode;
            }

            // support: ie<9
            // for mouse/key events, metakey==false if it's undefined (#3368, #11328)
            event.metakey = !!event.metakey;

            return fixhook.filter ? fixhook.filter( event, originalevent ) : event;
        },

        // includes some event props shared by keyevent and mouseevent
        props: "altkey bubbles cancelable ctrlkey currenttarget eventphase metakey relatedtarget shiftkey target timestamp view which".split(" "),

        fixhooks: {},

        keyhooks: {
            props: "char charcode key keycode".split(" "),
            filter: function( event, original ) {

                // add which for key events
                if ( event.which == null ) {
                    event.which = original.charcode != null ? original.charcode : original.keycode;
                }

                return event;
            }
        },

        mousehooks: {
            props: "button buttons clientx clienty fromelement offsetx offsety pagex pagey screenx screeny toelement".split(" "),
            filter: function( event, original ) {
                var body, eventdoc, doc,
                    button = original.button,
                    fromelement = original.fromelement;

                // calculate pagex/y if missing and clientx/y available
                if ( event.pagex == null && original.clientx != null ) {
                    eventdoc = event.target.ownerdocument || document;
                    doc = eventdoc.documentelement;
                    body = eventdoc.body;

                    event.pagex = original.clientx + ( doc && doc.scrollleft || body && body.scrollleft || 0 ) - ( doc && doc.clientleft || body && body.clientleft || 0 );
                    event.pagey = original.clienty + ( doc && doc.scrolltop  || body && body.scrolltop  || 0 ) - ( doc && doc.clienttop  || body && body.clienttop  || 0 );
                }

                // add relatedtarget, if necessary
                if ( !event.relatedtarget && fromelement ) {
                    event.relatedtarget = fromelement === event.target ? original.toelement : fromelement;
                }

                // add which for click: 1 === left; 2 === middle; 3 === right
                // note: button is not normalized, so don't use it
                if ( !event.which && button !== undefined ) {
                    event.which = ( button & 1 ? 1 : ( button & 2 ? 3 : ( button & 4 ? 2 : 0 ) ) );
                }

                return event;
            }
        },

        special: {
            load: {
                // prevent triggered image.load events from bubbling to window.load
                nobubble: true
            },
            focus: {
                // fire native event if possible so blur/focus sequence is correct
                trigger: function() {
                    if ( this !== safeactiveelement() && this.focus ) {
                        try {
                            this.focus();
                            return false;
                        } catch ( e ) {
                            // support: ie<9
                            // if we error on focus to hidden element (#1486, #12518),
                            // let .trigger() run the handlers
                        }
                    }
                },
                delegatetype: "focusin"
            },
            blur: {
                trigger: function() {
                    if ( this === safeactiveelement() && this.blur ) {
                        this.blur();
                        return false;
                    }
                },
                delegatetype: "focusout"
            },
            click: {
                // for checkbox, fire native event so checked state will be right
                trigger: function() {
                    if ( jquery.nodename( this, "input" ) && this.type === "checkbox" && this.click ) {
                        this.click();
                        return false;
                    }
                },

                // for cross-browser consistency, don't fire native .click() on links
                _default: function( event ) {
                    return jquery.nodename( event.target, "a" );
                }
            },

            beforeunload: {
                postdispatch: function( event ) {

                    // even when returnvalue equals to undefined firefox will still show alert
                    if ( event.result !== undefined ) {
                        event.originalevent.returnvalue = event.result;
                    }
                }
            }
        },

        simulate: function( type, elem, event, bubble ) {
            // piggyback on a donor event to simulate a different one.
            // fake originalevent to avoid donor's stoppropagation, but if the
            // simulated event prevents default then we do the same on the donor.
            var e = jquery.extend(
                new jquery.event(),
                event,
                {
                    type: type,
                    issimulated: true,
                    originalevent: {}
                }
            );
            if ( bubble ) {
                jquery.event.trigger( e, null, elem );
            } else {
                jquery.event.dispatch.call( elem, e );
            }
            if ( e.isdefaultprevented() ) {
                event.preventdefault();
            }
        }
    };

    jquery.removeevent = document.removeeventlistener ?
        function( elem, type, handle ) {
            if ( elem.removeeventlistener ) {
                elem.removeeventlistener( type, handle, false );
            }
        } :
        function( elem, type, handle ) {
            var name = "on" + type;

            if ( elem.detachevent ) {

                // #8545, #7054, preventing memory leaks for custom events in ie6-8
                // detachevent needed property on element, by name of that event, to properly expose it to gc
                if ( typeof elem[ name ] === core_strundefined ) {
                    elem[ name ] = null;
                }

                elem.detachevent( name, handle );
            }
        };

    jquery.event = function( src, props ) {
        // allow instantiation without the 'new' keyword
        if ( !(this instanceof jquery.event) ) {
            return new jquery.event( src, props );
        }

        // event object
        if ( src && src.type ) {
            this.originalevent = src;
            this.type = src.type;

            // events bubbling up the document may have been marked as prevented
            // by a handler lower down the tree; reflect the correct value.
            this.isdefaultprevented = ( src.defaultprevented || src.returnvalue === false ||
                src.getpreventdefault && src.getpreventdefault() ) ? returntrue : returnfalse;

            // event type
        } else {
            this.type = src;
        }

        // put explicitly provided properties onto the event object
        if ( props ) {
            jquery.extend( this, props );
        }

        // create a timestamp if incoming event doesn't have one
        this.timestamp = src && src.timestamp || jquery.now();

        // mark it as fixed
        this[ jquery.expando ] = true;
    };

// jquery.event is based on dom3 events as specified by the ecmascript language binding
// http://www.w3.org/tr/2003/wd-dom-level-3-events-20030331/ecma-script-binding.html
    jquery.event.prototype = {
        isdefaultprevented: returnfalse,
        ispropagationstopped: returnfalse,
        isimmediatepropagationstopped: returnfalse,

        preventdefault: function() {
            var e = this.originalevent;

            this.isdefaultprevented = returntrue;
            if ( !e ) {
                return;
            }

            // if preventdefault exists, run it on the original event
            if ( e.preventdefault ) {
                e.preventdefault();

                // support: ie
                // otherwise set the returnvalue property of the original event to false
            } else {
                e.returnvalue = false;
            }
        },
        stoppropagation: function() {
            var e = this.originalevent;

            this.ispropagationstopped = returntrue;
            if ( !e ) {
                return;
            }
            // if stoppropagation exists, run it on the original event
            if ( e.stoppropagation ) {
                e.stoppropagation();
            }

            // support: ie
            // set the cancelbubble property of the original event to true
            e.cancelbubble = true;
        },
        stopimmediatepropagation: function() {
            this.isimmediatepropagationstopped = returntrue;
            this.stoppropagation();
        }
    };

// create mouseenter/leave events using mouseover/out and event-time checks
    jquery.each({
        mouseenter: "mouseover",
        mouseleave: "mouseout"
    }, function( orig, fix ) {
        jquery.event.special[ orig ] = {
            delegatetype: fix,
            bindtype: fix,

            handle: function( event ) {
                var ret,
                    target = this,
                    related = event.relatedtarget,
                    handleobj = event.handleobj;

                // for mousenter/leave call the handler if related is outside the target.
                // nb: no relatedtarget if the mouse left/entered the browser window
                if ( !related || (related !== target && !jquery.contains( target, related )) ) {
                    event.type = handleobj.origtype;
                    ret = handleobj.handler.apply( this, arguments );
                    event.type = fix;
                }
                return ret;
            }
        };
    });

// ie submit delegation
    if ( !jquery.support.submitbubbles ) {

        jquery.event.special.submit = {
            setup: function() {
                // only need this for delegated form submit events
                if ( jquery.nodename( this, "form" ) ) {
                    return false;
                }

                // lazy-add a submit handler when a descendant form may potentially be submitted
                jquery.event.add( this, "click._submit keypress._submit", function( e ) {
                    // node name check avoids a vml-related crash in ie (#9807)
                    var elem = e.target,
                        form = jquery.nodename( elem, "input" ) || jquery.nodename( elem, "button" ) ? elem.form : undefined;
                    if ( form && !jquery._data( form, "submitbubbles" ) ) {
                        jquery.event.add( form, "submit._submit", function( event ) {
                            event._submit_bubble = true;
                        });
                        jquery._data( form, "submitbubbles", true );
                    }
                });
                // return undefined since we don't need an event listener
            },

            postdispatch: function( event ) {
                // if form was submitted by the user, bubble the event up the tree
                if ( event._submit_bubble ) {
                    delete event._submit_bubble;
                    if ( this.parentnode && !event.istrigger ) {
                        jquery.event.simulate( "submit", this.parentnode, event, true );
                    }
                }
            },

            teardown: function() {
                // only need this for delegated form submit events
                if ( jquery.nodename( this, "form" ) ) {
                    return false;
                }

                // remove delegated handlers; cleandata eventually reaps submit handlers attached above
                jquery.event.remove( this, "._submit" );
            }
        };
    }

// ie change delegation and checkbox/radio fix
    if ( !jquery.support.changebubbles ) {

        jquery.event.special.change = {

            setup: function() {

                if ( rformelems.test( this.nodename ) ) {
                    // ie doesn't fire change on a check/radio until blur; trigger it on click
                    // after a propertychange. eat the blur-change in special.change.handle.
                    // this still fires onchange a second time for check/radio after blur.
                    if ( this.type === "checkbox" || this.type === "radio" ) {
                        jquery.event.add( this, "propertychange._change", function( event ) {
                            if ( event.originalevent.propertyname === "checked" ) {
                                this._just_changed = true;
                            }
                        });
                        jquery.event.add( this, "click._change", function( event ) {
                            if ( this._just_changed && !event.istrigger ) {
                                this._just_changed = false;
                            }
                            // allow triggered, simulated change events (#11500)
                            jquery.event.simulate( "change", this, event, true );
                        });
                    }
                    return false;
                }
                // delegated event; lazy-add a change handler on descendant inputs
                jquery.event.add( this, "beforeactivate._change", function( e ) {
                    var elem = e.target;

                    if ( rformelems.test( elem.nodename ) && !jquery._data( elem, "changebubbles" ) ) {
                        jquery.event.add( elem, "change._change", function( event ) {
                            if ( this.parentnode && !event.issimulated && !event.istrigger ) {
                                jquery.event.simulate( "change", this.parentnode, event, true );
                            }
                        });
                        jquery._data( elem, "changebubbles", true );
                    }
                });
            },

            handle: function( event ) {
                var elem = event.target;

                // swallow native change events from checkbox/radio, we already triggered them above
                if ( this !== elem || event.issimulated || event.istrigger || (elem.type !== "radio" && elem.type !== "checkbox") ) {
                    return event.handleobj.handler.apply( this, arguments );
                }
            },

            teardown: function() {
                jquery.event.remove( this, "._change" );

                return !rformelems.test( this.nodename );
            }
        };
    }

// create "bubbling" focus and blur events
    if ( !jquery.support.focusinbubbles ) {
        jquery.each({ focus: "focusin", blur: "focusout" }, function( orig, fix ) {

            // attach a single capturing handler while someone wants focusin/focusout
            var attaches = 0,
                handler = function( event ) {
                    jquery.event.simulate( fix, event.target, jquery.event.fix( event ), true );
                };

            jquery.event.special[ fix ] = {
                setup: function() {
                    if ( attaches++ === 0 ) {
                        document.addeventlistener( orig, handler, true );
                    }
                },
                teardown: function() {
                    if ( --attaches === 0 ) {
                        document.removeeventlistener( orig, handler, true );
                    }
                }
            };
        });
    }

    jquery.fn.extend({

        on: function( types, selector, data, fn, /*internal*/ one ) {
            var type, origfn;

            // types can be a map of types/handlers
            if ( typeof types === "object" ) {
                // ( types-object, selector, data )
                if ( typeof selector !== "string" ) {
                    // ( types-object, data )
                    data = data || selector;
                    selector = undefined;
                }
                for ( type in types ) {
                    this.on( type, selector, data, types[ type ], one );
                }
                return this;
            }

            if ( data == null && fn == null ) {
                // ( types, fn )
                fn = selector;
                data = selector = undefined;
            } else if ( fn == null ) {
                if ( typeof selector === "string" ) {
                    // ( types, selector, fn )
                    fn = data;
                    data = undefined;
                } else {
                    // ( types, data, fn )
                    fn = data;
                    data = selector;
                    selector = undefined;
                }
            }
            if ( fn === false ) {
                fn = returnfalse;
            } else if ( !fn ) {
                return this;
            }

            if ( one === 1 ) {
                origfn = fn;
                fn = function( event ) {
                    // can use an empty set, since event contains the info
                    jquery().off( event );
                    return origfn.apply( this, arguments );
                };
                // use same guid so caller can remove using origfn
                fn.guid = origfn.guid || ( origfn.guid = jquery.guid++ );
            }
            return this.each( function() {
                jquery.event.add( this, types, fn, data, selector );
            });
        },
        one: function( types, selector, data, fn ) {
            return this.on( types, selector, data, fn, 1 );
        },
        off: function( types, selector, fn ) {
            var handleobj, type;
            if ( types && types.preventdefault && types.handleobj ) {
                // ( event )  dispatched jquery.event
                handleobj = types.handleobj;
                jquery( types.delegatetarget ).off(
                    handleobj.namespace ? handleobj.origtype + "." + handleobj.namespace : handleobj.origtype,
                    handleobj.selector,
                    handleobj.handler
                );
                return this;
            }
            if ( typeof types === "object" ) {
                // ( types-object [, selector] )
                for ( type in types ) {
                    this.off( type, selector, types[ type ] );
                }
                return this;
            }
            if ( selector === false || typeof selector === "function" ) {
                // ( types [, fn] )
                fn = selector;
                selector = undefined;
            }
            if ( fn === false ) {
                fn = returnfalse;
            }
            return this.each(function() {
                jquery.event.remove( this, types, fn, selector );
            });
        },

        trigger: function( type, data ) {
            return this.each(function() {
                jquery.event.trigger( type, data, this );
            });
        },
        triggerhandler: function( type, data ) {
            var elem = this[0];
            if ( elem ) {
                return jquery.event.trigger( type, data, elem, true );
            }
        }
    });
    var issimple = /^.[^:#\[\.,]*$/,
        rparentsprev = /^(?:parents|prev(?:until|all))/,
        rneedscontext = jquery.expr.match.needscontext,
    // methods guaranteed to produce a unique set when starting from a unique set
        guaranteedunique = {
            children: true,
            contents: true,
            next: true,
            prev: true
        };

    jquery.fn.extend({
        find: function( selector ) {
            var i,
                ret = [],
                self = this,
                len = self.length;

            if ( typeof selector !== "string" ) {
                return this.pushstack( jquery( selector ).filter(function() {
                    for ( i = 0; i < len; i++ ) {
                        if ( jquery.contains( self[ i ], this ) ) {
                            return true;
                        }
                    }
                }) );
            }

            for ( i = 0; i < len; i++ ) {
                jquery.find( selector, self[ i ], ret );
            }

            // needed because $( selector, context ) becomes $( context ).find( selector )
            ret = this.pushstack( len > 1 ? jquery.unique( ret ) : ret );
            ret.selector = this.selector ? this.selector + " " + selector : selector;
            return ret;
        },

        has: function( target ) {
            var i,
                targets = jquery( target, this ),
                len = targets.length;

            return this.filter(function() {
                for ( i = 0; i < len; i++ ) {
                    if ( jquery.contains( this, targets[i] ) ) {
                        return true;
                    }
                }
            });
        },

        not: function( selector ) {
            return this.pushstack( winnow(this, selector || [], true) );
        },

        filter: function( selector ) {
            return this.pushstack( winnow(this, selector || [], false) );
        },

        is: function( selector ) {
            return !!winnow(
                this,

                // if this is a positional/relative selector, check membership in the returned set
                // so $("p:first").is("p:last") won't return true for a doc with two "p".
                    typeof selector === "string" && rneedscontext.test( selector ) ?
                    jquery( selector ) :
                    selector || [],
                false
            ).length;
        },

        closest: function( selectors, context ) {
            var cur,
                i = 0,
                l = this.length,
                ret = [],
                pos = rneedscontext.test( selectors ) || typeof selectors !== "string" ?
                    jquery( selectors, context || this.context ) :
                    0;

            for ( ; i < l; i++ ) {
                for ( cur = this[i]; cur && cur !== context; cur = cur.parentnode ) {
                    // always skip document fragments
                    if ( cur.nodetype < 11 && (pos ?
                        pos.index(cur) > -1 :

                        // don't pass non-elements to sizzle
                        cur.nodetype === 1 &&
                        jquery.find.matchesselector(cur, selectors)) ) {

                        cur = ret.push( cur );
                        break;
                    }
                }
            }

            return this.pushstack( ret.length > 1 ? jquery.unique( ret ) : ret );
        },

        // determine the position of an element within
        // the matched set of elements
        index: function( elem ) {

            // no argument, return index in parent
            if ( !elem ) {
                return ( this[0] && this[0].parentnode ) ? this.first().prevall().length : -1;
            }

            // index in selector
            if ( typeof elem === "string" ) {
                return jquery.inarray( this[0], jquery( elem ) );
            }

            // locate the position of the desired element
            return jquery.inarray(
                // if it receives a jquery object, the first element is used
                elem.jquery ? elem[0] : elem, this );
        },

        add: function( selector, context ) {
            var set = typeof selector === "string" ?
                    jquery( selector, context ) :
                    jquery.makearray( selector && selector.nodetype ? [ selector ] : selector ),
                all = jquery.merge( this.get(), set );

            return this.pushstack( jquery.unique(all) );
        },

        addback: function( selector ) {
            return this.add( selector == null ?
                    this.prevobject : this.prevobject.filter(selector)
            );
        }
    });

    function sibling( cur, dir ) {
        do {
            cur = cur[ dir ];
        } while ( cur && cur.nodetype !== 1 );

        return cur;
    }

    jquery.each({
        parent: function( elem ) {
            var parent = elem.parentnode;
            return parent && parent.nodetype !== 11 ? parent : null;
        },
        parents: function( elem ) {
            return jquery.dir( elem, "parentnode" );
        },
        parentsuntil: function( elem, i, until ) {
            return jquery.dir( elem, "parentnode", until );
        },
        next: function( elem ) {
            return sibling( elem, "nextsibling" );
        },
        prev: function( elem ) {
            return sibling( elem, "previoussibling" );
        },
        nextall: function( elem ) {
            return jquery.dir( elem, "nextsibling" );
        },
        prevall: function( elem ) {
            return jquery.dir( elem, "previoussibling" );
        },
        nextuntil: function( elem, i, until ) {
            return jquery.dir( elem, "nextsibling", until );
        },
        prevuntil: function( elem, i, until ) {
            return jquery.dir( elem, "previoussibling", until );
        },
        siblings: function( elem ) {
            return jquery.sibling( ( elem.parentnode || {} ).firstchild, elem );
        },
        children: function( elem ) {
            return jquery.sibling( elem.firstchild );
        },
        contents: function( elem ) {
            return jquery.nodename( elem, "iframe" ) ?
                elem.contentdocument || elem.contentwindow.document :
                jquery.merge( [], elem.childnodes );
        }
    }, function( name, fn ) {
        jquery.fn[ name ] = function( until, selector ) {
            var ret = jquery.map( this, fn, until );

            if ( name.slice( -5 ) !== "until" ) {
                selector = until;
            }

            if ( selector && typeof selector === "string" ) {
                ret = jquery.filter( selector, ret );
            }

            if ( this.length > 1 ) {
                // remove duplicates
                if ( !guaranteedunique[ name ] ) {
                    ret = jquery.unique( ret );
                }

                // reverse order for parents* and prev-derivatives
                if ( rparentsprev.test( name ) ) {
                    ret = ret.reverse();
                }
            }

            return this.pushstack( ret );
        };
    });

    jquery.extend({
        filter: function( expr, elems, not ) {
            var elem = elems[ 0 ];

            if ( not ) {
                expr = ":not(" + expr + ")";
            }

            return elems.length === 1 && elem.nodetype === 1 ?
                jquery.find.matchesselector( elem, expr ) ? [ elem ] : [] :
                jquery.find.matches( expr, jquery.grep( elems, function( elem ) {
                    return elem.nodetype === 1;
                }));
        },

        dir: function( elem, dir, until ) {
            var matched = [],
                cur = elem[ dir ];

            while ( cur && cur.nodetype !== 9 && (until === undefined || cur.nodetype !== 1 || !jquery( cur ).is( until )) ) {
                if ( cur.nodetype === 1 ) {
                    matched.push( cur );
                }
                cur = cur[dir];
            }
            return matched;
        },

        sibling: function( n, elem ) {
            var r = [];

            for ( ; n; n = n.nextsibling ) {
                if ( n.nodetype === 1 && n !== elem ) {
                    r.push( n );
                }
            }

            return r;
        }
    });

// implement the identical functionality for filter and not
    function winnow( elements, qualifier, not ) {
        if ( jquery.isfunction( qualifier ) ) {
            return jquery.grep( elements, function( elem, i ) {
                /* jshint -w018 */
                return !!qualifier.call( elem, i, elem ) !== not;
            });

        }

        if ( qualifier.nodetype ) {
            return jquery.grep( elements, function( elem ) {
                return ( elem === qualifier ) !== not;
            });

        }

        if ( typeof qualifier === "string" ) {
            if ( issimple.test( qualifier ) ) {
                return jquery.filter( qualifier, elements, not );
            }

            qualifier = jquery.filter( qualifier, elements );
        }

        return jquery.grep( elements, function( elem ) {
            return ( jquery.inarray( elem, qualifier ) >= 0 ) !== not;
        });
    }
    function createsafefragment( document ) {
        var list = nodenames.split( "|" ),
            safefrag = document.createdocumentfragment();

        if ( safefrag.createelement ) {
            while ( list.length ) {
                safefrag.createelement(
                    list.pop()
                );
            }
        }
        return safefrag;
    }

    var nodenames = "abbr|article|aside|audio|bdi|canvas|data|datalist|details|figcaption|figure|footer|" +
            "header|hgroup|mark|meter|nav|output|progress|section|summary|time|video",
        rinlinejquery = / jquery\d+="(?:null|\d+)"/g,
        rnoshimcache = new regexp("<(?:" + nodenames + ")[\\s/>]", "i"),
        rleadingwhitespace = /^\s+/,
        rxhtmltag = /<(?!area|br|col|embed|hr|img|input|link|meta|param)(([\w:]+)[^>]*)\/>/gi,
        rtagname = /<([\w:]+)/,
        rtbody = /<tbody/i,
        rhtml = /<|&#?\w+;/,
        rnoinnerhtml = /<(?:script|style|link)/i,
        manipulation_rcheckabletype = /^(?:checkbox|radio)$/i,
    // checked="checked" or checked
        rchecked = /checked\s*(?:[^=]|=\s*.checked.)/i,
        rscripttype = /^$|\/(?:java|ecma)script/i,
        rscripttypemasked = /^true\/(.*)/,
        rcleanscript = /^\s*<!(?:\[cdata\[|--)|(?:\]\]|--)>\s*$/g,

    // we have to close these tags to support xhtml (#13200)
        wrapmap = {
            option: [ 1, "<select multiple='multiple'>", "</select>" ],
            legend: [ 1, "<fieldset>", "</fieldset>" ],
            area: [ 1, "<map>", "</map>" ],
            param: [ 1, "<object>", "</object>" ],
            thead: [ 1, "<table>", "</table>" ],
            tr: [ 2, "<table><tbody>", "</tbody></table>" ],
            col: [ 2, "<table><tbody></tbody><colgroup>", "</colgroup></table>" ],
            td: [ 3, "<table><tbody><tr>", "</tr></tbody></table>" ],

            // ie6-8 can't serialize link, script, style, or any html5 (noscope) tags,
            // unless wrapped in a div with non-breaking characters in front of it.
            _default: jquery.support.htmlserialize ? [ 0, "", "" ] : [ 1, "x<div>", "</div>"  ]
        },
        safefragment = createsafefragment( document ),
        fragmentdiv = safefragment.appendchild( document.createelement("div") );

    wrapmap.optgroup = wrapmap.option;
    wrapmap.tbody = wrapmap.tfoot = wrapmap.colgroup = wrapmap.caption = wrapmap.thead;
    wrapmap.th = wrapmap.td;

    jquery.fn.extend({
        text: function( value ) {
            return jquery.access( this, function( value ) {
                return value === undefined ?
                    jquery.text( this ) :
                    this.empty().append( ( this[0] && this[0].ownerdocument || document ).createtextnode( value ) );
            }, null, value, arguments.length );
        },

        append: function() {
            return this.dommanip( arguments, function( elem ) {
                if ( this.nodetype === 1 || this.nodetype === 11 || this.nodetype === 9 ) {
                    var target = manipulationtarget( this, elem );
                    target.appendchild( elem );
                }
            });
        },

        prepend: function() {
            return this.dommanip( arguments, function( elem ) {
                if ( this.nodetype === 1 || this.nodetype === 11 || this.nodetype === 9 ) {
                    var target = manipulationtarget( this, elem );
                    target.insertbefore( elem, target.firstchild );
                }
            });
        },

        before: function() {
            return this.dommanip( arguments, function( elem ) {
                if ( this.parentnode ) {
                    this.parentnode.insertbefore( elem, this );
                }
            });
        },

        after: function() {
            return this.dommanip( arguments, function( elem ) {
                if ( this.parentnode ) {
                    this.parentnode.insertbefore( elem, this.nextsibling );
                }
            });
        },

        // keepdata is for internal use only--do not document
        remove: function( selector, keepdata ) {
            var elem,
                elems = selector ? jquery.filter( selector, this ) : this,
                i = 0;

            for ( ; (elem = elems[i]) != null; i++ ) {

                if ( !keepdata && elem.nodetype === 1 ) {
                    jquery.cleandata( getall( elem ) );
                }

                if ( elem.parentnode ) {
                    if ( keepdata && jquery.contains( elem.ownerdocument, elem ) ) {
                        setglobaleval( getall( elem, "script" ) );
                    }
                    elem.parentnode.removechild( elem );
                }
            }

            return this;
        },

        empty: function() {
            var elem,
                i = 0;

            for ( ; (elem = this[i]) != null; i++ ) {
                // remove element nodes and prevent memory leaks
                if ( elem.nodetype === 1 ) {
                    jquery.cleandata( getall( elem, false ) );
                }

                // remove any remaining nodes
                while ( elem.firstchild ) {
                    elem.removechild( elem.firstchild );
                }

                // if this is a select, ensure that it displays empty (#12336)
                // support: ie<9
                if ( elem.options && jquery.nodename( elem, "select" ) ) {
                    elem.options.length = 0;
                }
            }

            return this;
        },

        clone: function( dataandevents, deepdataandevents ) {
            dataandevents = dataandevents == null ? false : dataandevents;
            deepdataandevents = deepdataandevents == null ? dataandevents : deepdataandevents;

            return this.map( function () {
                return jquery.clone( this, dataandevents, deepdataandevents );
            });
        },

        html: function( value ) {
            return jquery.access( this, function( value ) {
                var elem = this[0] || {},
                    i = 0,
                    l = this.length;

                if ( value === undefined ) {
                    return elem.nodetype === 1 ?
                        elem.innerhtml.replace( rinlinejquery, "" ) :
                        undefined;
                }

                // see if we can take a shortcut and just use innerhtml
                if ( typeof value === "string" && !rnoinnerhtml.test( value ) &&
                    ( jquery.support.htmlserialize || !rnoshimcache.test( value )  ) &&
                    ( jquery.support.leadingwhitespace || !rleadingwhitespace.test( value ) ) &&
                    !wrapmap[ ( rtagname.exec( value ) || ["", ""] )[1].tolowercase() ] ) {

                    value = value.replace( rxhtmltag, "<$1></$2>" );

                    try {
                        for (; i < l; i++ ) {
                            // remove element nodes and prevent memory leaks
                            elem = this[i] || {};
                            if ( elem.nodetype === 1 ) {
                                jquery.cleandata( getall( elem, false ) );
                                elem.innerhtml = value;
                            }
                        }

                        elem = 0;

                        // if using innerhtml throws an exception, use the fallback method
                    } catch(e) {}
                }

                if ( elem ) {
                    this.empty().append( value );
                }
            }, null, value, arguments.length );
        },

        replacewith: function() {
            var
            // snapshot the dom in case .dommanip sweeps something relevant into its fragment
                args = jquery.map( this, function( elem ) {
                    return [ elem.nextsibling, elem.parentnode ];
                }),
                i = 0;

            // make the changes, replacing each context element with the new content
            this.dommanip( arguments, function( elem ) {
                var next = args[ i++ ],
                    parent = args[ i++ ];

                if ( parent ) {
                    // don't use the snapshot next if it has moved (#13810)
                    if ( next && next.parentnode !== parent ) {
                        next = this.nextsibling;
                    }
                    jquery( this ).remove();
                    parent.insertbefore( elem, next );
                }
                // allow new content to include elements from the context set
            }, true );

            // force removal if there was no new content (e.g., from empty arguments)
            return i ? this : this.remove();
        },

        detach: function( selector ) {
            return this.remove( selector, true );
        },

        dommanip: function( args, callback, allowintersection ) {

            // flatten any nested arrays
            args = core_concat.apply( [], args );

            var first, node, hasscripts,
                scripts, doc, fragment,
                i = 0,
                l = this.length,
                set = this,
                inoclone = l - 1,
                value = args[0],
                isfunction = jquery.isfunction( value );

            // we can't clonenode fragments that contain checked, in webkit
            if ( isfunction || !( l <= 1 || typeof value !== "string" || jquery.support.checkclone || !rchecked.test( value ) ) ) {
                return this.each(function( index ) {
                    var self = set.eq( index );
                    if ( isfunction ) {
                        args[0] = value.call( this, index, self.html() );
                    }
                    self.dommanip( args, callback, allowintersection );
                });
            }

            if ( l ) {
                fragment = jquery.buildfragment( args, this[ 0 ].ownerdocument, false, !allowintersection && this );
                first = fragment.firstchild;

                if ( fragment.childnodes.length === 1 ) {
                    fragment = first;
                }

                if ( first ) {
                    scripts = jquery.map( getall( fragment, "script" ), disablescript );
                    hasscripts = scripts.length;

                    // use the original fragment for the last item instead of the first because it can end up
                    // being emptied incorrectly in certain situations (#8070).
                    for ( ; i < l; i++ ) {
                        node = fragment;

                        if ( i !== inoclone ) {
                            node = jquery.clone( node, true, true );

                            // keep references to cloned scripts for later restoration
                            if ( hasscripts ) {
                                jquery.merge( scripts, getall( node, "script" ) );
                            }
                        }

                        callback.call( this[i], node, i );
                    }

                    if ( hasscripts ) {
                        doc = scripts[ scripts.length - 1 ].ownerdocument;

                        // reenable scripts
                        jquery.map( scripts, restorescript );

                        // evaluate executable scripts on first document insertion
                        for ( i = 0; i < hasscripts; i++ ) {
                            node = scripts[ i ];
                            if ( rscripttype.test( node.type || "" ) &&
                                !jquery._data( node, "globaleval" ) && jquery.contains( doc, node ) ) {

                                if ( node.src ) {
                                    // hope ajax is available...
                                    jquery._evalurl( node.src );
                                } else {
                                    jquery.globaleval( ( node.text || node.textcontent || node.innerhtml || "" ).replace( rcleanscript, "" ) );
                                }
                            }
                        }
                    }

                    // fix #11809: avoid leaking memory
                    fragment = first = null;
                }
            }

            return this;
        }
    });

// support: ie<8
// manipulating tables requires a tbody
    function manipulationtarget( elem, content ) {
        return jquery.nodename( elem, "table" ) &&
            jquery.nodename( content.nodetype === 1 ? content : content.firstchild, "tr" ) ?

            elem.getelementsbytagname("tbody")[0] ||
            elem.appendchild( elem.ownerdocument.createelement("tbody") ) :
            elem;
    }

// replace/restore the type attribute of script elements for safe dom manipulation
    function disablescript( elem ) {
        elem.type = (jquery.find.attr( elem, "type" ) !== null) + "/" + elem.type;
        return elem;
    }
    function restorescript( elem ) {
        var match = rscripttypemasked.exec( elem.type );
        if ( match ) {
            elem.type = match[1];
        } else {
            elem.removeattribute("type");
        }
        return elem;
    }

// mark scripts as having already been evaluated
    function setglobaleval( elems, refelements ) {
        var elem,
            i = 0;
        for ( ; (elem = elems[i]) != null; i++ ) {
            jquery._data( elem, "globaleval", !refelements || jquery._data( refelements[i], "globaleval" ) );
        }
    }

    function clonecopyevent( src, dest ) {

        if ( dest.nodetype !== 1 || !jquery.hasdata( src ) ) {
            return;
        }

        var type, i, l,
            olddata = jquery._data( src ),
            curdata = jquery._data( dest, olddata ),
            events = olddata.events;

        if ( events ) {
            delete curdata.handle;
            curdata.events = {};

            for ( type in events ) {
                for ( i = 0, l = events[ type ].length; i < l; i++ ) {
                    jquery.event.add( dest, type, events[ type ][ i ] );
                }
            }
        }

        // make the cloned public data object a copy from the original
        if ( curdata.data ) {
            curdata.data = jquery.extend( {}, curdata.data );
        }
    }

    function fixclonenodeissues( src, dest ) {
        var nodename, e, data;

        // we do not need to do anything for non-elements
        if ( dest.nodetype !== 1 ) {
            return;
        }

        nodename = dest.nodename.tolowercase();

        // ie6-8 copies events bound via attachevent when using clonenode.
        if ( !jquery.support.nocloneevent && dest[ jquery.expando ] ) {
            data = jquery._data( dest );

            for ( e in data.events ) {
                jquery.removeevent( dest, e, data.handle );
            }

            // event data gets referenced instead of copied if the expando gets copied too
            dest.removeattribute( jquery.expando );
        }

        // ie blanks contents when cloning scripts, and tries to evaluate newly-set text
        if ( nodename === "script" && dest.text !== src.text ) {
            disablescript( dest ).text = src.text;
            restorescript( dest );

            // ie6-10 improperly clones children of object elements using classid.
            // ie10 throws nomodificationallowederror if parent is null, #12132.
        } else if ( nodename === "object" ) {
            if ( dest.parentnode ) {
                dest.outerhtml = src.outerhtml;
            }

            // this path appears unavoidable for ie9. when cloning an object
            // element in ie9, the outerhtml strategy above is not sufficient.
            // if the src has innerhtml and the destination does not,
            // copy the src.innerhtml into the dest.innerhtml. #10324
            if ( jquery.support.html5clone && ( src.innerhtml && !jquery.trim(dest.innerhtml) ) ) {
                dest.innerhtml = src.innerhtml;
            }

        } else if ( nodename === "input" && manipulation_rcheckabletype.test( src.type ) ) {
            // ie6-8 fails to persist the checked state of a cloned checkbox
            // or radio button. worse, ie6-7 fail to give the cloned element
            // a checked appearance if the defaultchecked value isn't also set

            dest.defaultchecked = dest.checked = src.checked;

            // ie6-7 get confused and end up setting the value of a cloned
            // checkbox/radio button to an empty string instead of "on"
            if ( dest.value !== src.value ) {
                dest.value = src.value;
            }

            // ie6-8 fails to return the selected option to the default selected
            // state when cloning options
        } else if ( nodename === "option" ) {
            dest.defaultselected = dest.selected = src.defaultselected;

            // ie6-8 fails to set the defaultvalue to the correct value when
            // cloning other types of input fields
        } else if ( nodename === "input" || nodename === "textarea" ) {
            dest.defaultvalue = src.defaultvalue;
        }
    }

    jquery.each({
        appendto: "append",
        prependto: "prepend",
        insertbefore: "before",
        insertafter: "after",
        replaceall: "replacewith"
    }, function( name, original ) {
        jquery.fn[ name ] = function( selector ) {
            var elems,
                i = 0,
                ret = [],
                insert = jquery( selector ),
                last = insert.length - 1;

            for ( ; i <= last; i++ ) {
                elems = i === last ? this : this.clone(true);
                jquery( insert[i] )[ original ]( elems );

                // modern browsers can apply jquery collections as arrays, but oldie needs a .get()
                core_push.apply( ret, elems.get() );
            }

            return this.pushstack( ret );
        };
    });

    function getall( context, tag ) {
        var elems, elem,
            i = 0,
            found = typeof context.getelementsbytagname !== core_strundefined ? context.getelementsbytagname( tag || "*" ) :
                    typeof context.queryselectorall !== core_strundefined ? context.queryselectorall( tag || "*" ) :
                undefined;

        if ( !found ) {
            for ( found = [], elems = context.childnodes || context; (elem = elems[i]) != null; i++ ) {
                if ( !tag || jquery.nodename( elem, tag ) ) {
                    found.push( elem );
                } else {
                    jquery.merge( found, getall( elem, tag ) );
                }
            }
        }

        return tag === undefined || tag && jquery.nodename( context, tag ) ?
            jquery.merge( [ context ], found ) :
            found;
    }

// used in buildfragment, fixes the defaultchecked property
    function fixdefaultchecked( elem ) {
        if ( manipulation_rcheckabletype.test( elem.type ) ) {
            elem.defaultchecked = elem.checked;
        }
    }

    jquery.extend({
        clone: function( elem, dataandevents, deepdataandevents ) {
            var destelements, node, clone, i, srcelements,
                inpage = jquery.contains( elem.ownerdocument, elem );

            if ( jquery.support.html5clone || jquery.isxmldoc(elem) || !rnoshimcache.test( "<" + elem.nodename + ">" ) ) {
                clone = elem.clonenode( true );

                // ie<=8 does not properly clone detached, unknown element nodes
            } else {
                fragmentdiv.innerhtml = elem.outerhtml;
                fragmentdiv.removechild( clone = fragmentdiv.firstchild );
            }

            if ( (!jquery.support.nocloneevent || !jquery.support.noclonechecked) &&
                (elem.nodetype === 1 || elem.nodetype === 11) && !jquery.isxmldoc(elem) ) {

                // we eschew sizzle here for performance reasons: http://jsperf.com/getall-vs-sizzle/2
                destelements = getall( clone );
                srcelements = getall( elem );

                // fix all ie cloning issues
                for ( i = 0; (node = srcelements[i]) != null; ++i ) {
                    // ensure that the destination node is not null; fixes #9587
                    if ( destelements[i] ) {
                        fixclonenodeissues( node, destelements[i] );
                    }
                }
            }

            // copy the events from the original to the clone
            if ( dataandevents ) {
                if ( deepdataandevents ) {
                    srcelements = srcelements || getall( elem );
                    destelements = destelements || getall( clone );

                    for ( i = 0; (node = srcelements[i]) != null; i++ ) {
                        clonecopyevent( node, destelements[i] );
                    }
                } else {
                    clonecopyevent( elem, clone );
                }
            }

            // preserve script evaluation history
            destelements = getall( clone, "script" );
            if ( destelements.length > 0 ) {
                setglobaleval( destelements, !inpage && getall( elem, "script" ) );
            }

            destelements = srcelements = node = null;

            // return the cloned set
            return clone;
        },

        buildfragment: function( elems, context, scripts, selection ) {
            var j, elem, contains,
                tmp, tag, tbody, wrap,
                l = elems.length,

            // ensure a safe fragment
                safe = createsafefragment( context ),

                nodes = [],
                i = 0;

            for ( ; i < l; i++ ) {
                elem = elems[ i ];

                if ( elem || elem === 0 ) {

                    // add nodes directly
                    if ( jquery.type( elem ) === "object" ) {
                        jquery.merge( nodes, elem.nodetype ? [ elem ] : elem );

                        // convert non-html into a text node
                    } else if ( !rhtml.test( elem ) ) {
                        nodes.push( context.createtextnode( elem ) );

                        // convert html into dom nodes
                    } else {
                        tmp = tmp || safe.appendchild( context.createelement("div") );

                        // deserialize a standard representation
                        tag = ( rtagname.exec( elem ) || ["", ""] )[1].tolowercase();
                        wrap = wrapmap[ tag ] || wrapmap._default;

                        tmp.innerhtml = wrap[1] + elem.replace( rxhtmltag, "<$1></$2>" ) + wrap[2];

                        // descend through wrappers to the right content
                        j = wrap[0];
                        while ( j-- ) {
                            tmp = tmp.lastchild;
                        }

                        // manually add leading whitespace removed by ie
                        if ( !jquery.support.leadingwhitespace && rleadingwhitespace.test( elem ) ) {
                            nodes.push( context.createtextnode( rleadingwhitespace.exec( elem )[0] ) );
                        }

                        // remove ie's autoinserted <tbody> from table fragments
                        if ( !jquery.support.tbody ) {

                            // string was a <table>, *may* have spurious <tbody>
                            elem = tag === "table" && !rtbody.test( elem ) ?
                                tmp.firstchild :

                                // string was a bare <thead> or <tfoot>
                                    wrap[1] === "<table>" && !rtbody.test( elem ) ?
                                tmp :
                                0;

                            j = elem && elem.childnodes.length;
                            while ( j-- ) {
                                if ( jquery.nodename( (tbody = elem.childnodes[j]), "tbody" ) && !tbody.childnodes.length ) {
                                    elem.removechild( tbody );
                                }
                            }
                        }

                        jquery.merge( nodes, tmp.childnodes );

                        // fix #12392 for webkit and ie > 9
                        tmp.textcontent = "";

                        // fix #12392 for oldie
                        while ( tmp.firstchild ) {
                            tmp.removechild( tmp.firstchild );
                        }

                        // remember the top-level container for proper cleanup
                        tmp = safe.lastchild;
                    }
                }
            }

            // fix #11356: clear elements from fragment
            if ( tmp ) {
                safe.removechild( tmp );
            }

            // reset defaultchecked for any radios and checkboxes
            // about to be appended to the dom in ie 6/7 (#8060)
            if ( !jquery.support.appendchecked ) {
                jquery.grep( getall( nodes, "input" ), fixdefaultchecked );
            }

            i = 0;
            while ( (elem = nodes[ i++ ]) ) {

                // #4087 - if origin and destination elements are the same, and this is
                // that element, do not do anything
                if ( selection && jquery.inarray( elem, selection ) !== -1 ) {
                    continue;
                }

                contains = jquery.contains( elem.ownerdocument, elem );

                // append to fragment
                tmp = getall( safe.appendchild( elem ), "script" );

                // preserve script evaluation history
                if ( contains ) {
                    setglobaleval( tmp );
                }

                // capture executables
                if ( scripts ) {
                    j = 0;
                    while ( (elem = tmp[ j++ ]) ) {
                        if ( rscripttype.test( elem.type || "" ) ) {
                            scripts.push( elem );
                        }
                    }
                }
            }

            tmp = null;

            return safe;
        },

        cleandata: function( elems, /* internal */ acceptdata ) {
            var elem, type, id, data,
                i = 0,
                internalkey = jquery.expando,
                cache = jquery.cache,
                deleteexpando = jquery.support.deleteexpando,
                special = jquery.event.special;

            for ( ; (elem = elems[i]) != null; i++ ) {

                if ( acceptdata || jquery.acceptdata( elem ) ) {

                    id = elem[ internalkey ];
                    data = id && cache[ id ];

                    if ( data ) {
                        if ( data.events ) {
                            for ( type in data.events ) {
                                if ( special[ type ] ) {
                                    jquery.event.remove( elem, type );

                                    // this is a shortcut to avoid jquery.event.remove's overhead
                                } else {
                                    jquery.removeevent( elem, type, data.handle );
                                }
                            }
                        }

                        // remove cache only if it was not already removed by jquery.event.remove
                        if ( cache[ id ] ) {

                            delete cache[ id ];

                            // ie does not allow us to delete expando properties from nodes,
                            // nor does it have a removeattribute function on document nodes;
                            // we must handle all of these cases
                            if ( deleteexpando ) {
                                delete elem[ internalkey ];

                            } else if ( typeof elem.removeattribute !== core_strundefined ) {
                                elem.removeattribute( internalkey );

                            } else {
                                elem[ internalkey ] = null;
                            }

                            core_deletedids.push( id );
                        }
                    }
                }
            }
        },

        _evalurl: function( url ) {
            return jquery.ajax({
                url: url,
                type: "get",
                datatype: "script",
                async: false,
                global: false,
                "throws": true
            });
        }
    });
    jquery.fn.extend({
        wrapall: function( html ) {
            if ( jquery.isfunction( html ) ) {
                return this.each(function(i) {
                    jquery(this).wrapall( html.call(this, i) );
                });
            }

            if ( this[0] ) {
                // the elements to wrap the target around
                var wrap = jquery( html, this[0].ownerdocument ).eq(0).clone(true);

                if ( this[0].parentnode ) {
                    wrap.insertbefore( this[0] );
                }

                wrap.map(function() {
                    var elem = this;

                    while ( elem.firstchild && elem.firstchild.nodetype === 1 ) {
                        elem = elem.firstchild;
                    }

                    return elem;
                }).append( this );
            }

            return this;
        },

        wrapinner: function( html ) {
            if ( jquery.isfunction( html ) ) {
                return this.each(function(i) {
                    jquery(this).wrapinner( html.call(this, i) );
                });
            }

            return this.each(function() {
                var self = jquery( this ),
                    contents = self.contents();

                if ( contents.length ) {
                    contents.wrapall( html );

                } else {
                    self.append( html );
                }
            });
        },

        wrap: function( html ) {
            var isfunction = jquery.isfunction( html );

            return this.each(function(i) {
                jquery( this ).wrapall( isfunction ? html.call(this, i) : html );
            });
        },

        unwrap: function() {
            return this.parent().each(function() {
                if ( !jquery.nodename( this, "body" ) ) {
                    jquery( this ).replacewith( this.childnodes );
                }
            }).end();
        }
    });
    var iframe, getstyles, curcss,
        ralpha = /alpha\([^)]*\)/i,
        ropacity = /opacity\s*=\s*([^)]*)/,
        rposition = /^(top|right|bottom|left)$/,
    // swappable if display is none or starts with table except "table", "table-cell", or "table-caption"
    // see here for display values: https://developer.mozilla.org/en-us/docs/css/display
        rdisplayswap = /^(none|table(?!-c[ea]).+)/,
        rmargin = /^margin/,
        rnumsplit = new regexp( "^(" + core_pnum + ")(.*)$", "i" ),
        rnumnonpx = new regexp( "^(" + core_pnum + ")(?!px)[a-z%]+$", "i" ),
        rrelnum = new regexp( "^([+-])=(" + core_pnum + ")", "i" ),
        elemdisplay = { body: "block" },

        cssshow = { position: "absolute", visibility: "hidden", display: "block" },
        cssnormaltransform = {
            letterspacing: 0,
            fontweight: 400
        },

        cssexpand = [ "top", "right", "bottom", "left" ],
        cssprefixes = [ "webkit", "o", "moz", "ms" ];

// return a css property mapped to a potentially vendor prefixed property
    function vendorpropname( style, name ) {

        // shortcut for names that are not vendor prefixed
        if ( name in style ) {
            return name;
        }

        // check for vendor prefixed names
        var capname = name.charat(0).touppercase() + name.slice(1),
            origname = name,
            i = cssprefixes.length;

        while ( i-- ) {
            name = cssprefixes[ i ] + capname;
            if ( name in style ) {
                return name;
            }
        }

        return origname;
    }

    function ishidden( elem, el ) {
        // ishidden might be called from jquery#filter function;
        // in that case, element will be second argument
        elem = el || elem;
        return jquery.css( elem, "display" ) === "none" || !jquery.contains( elem.ownerdocument, elem );
    }

    function showhide( elements, show ) {
        var display, elem, hidden,
            values = [],
            index = 0,
            length = elements.length;

        for ( ; index < length; index++ ) {
            elem = elements[ index ];
            if ( !elem.style ) {
                continue;
            }

            values[ index ] = jquery._data( elem, "olddisplay" );
            display = elem.style.display;
            if ( show ) {
                // reset the inline display of this element to learn if it is
                // being hidden by cascaded rules or not
                if ( !values[ index ] && display === "none" ) {
                    elem.style.display = "";
                }

                // set elements which have been overridden with display: none
                // in a stylesheet to whatever the default browser style is
                // for such an element
                if ( elem.style.display === "" && ishidden( elem ) ) {
                    values[ index ] = jquery._data( elem, "olddisplay", css_defaultdisplay(elem.nodename) );
                }
            } else {

                if ( !values[ index ] ) {
                    hidden = ishidden( elem );

                    if ( display && display !== "none" || !hidden ) {
                        jquery._data( elem, "olddisplay", hidden ? display : jquery.css( elem, "display" ) );
                    }
                }
            }
        }

        // set the display of most of the elements in a second loop
        // to avoid the constant reflow
        for ( index = 0; index < length; index++ ) {
            elem = elements[ index ];
            if ( !elem.style ) {
                continue;
            }
            if ( !show || elem.style.display === "none" || elem.style.display === "" ) {
                elem.style.display = show ? values[ index ] || "" : "none";
            }
        }

        return elements;
    }

    jquery.fn.extend({
        css: function( name, value ) {
            return jquery.access( this, function( elem, name, value ) {
                var len, styles,
                    map = {},
                    i = 0;

                if ( jquery.isarray( name ) ) {
                    styles = getstyles( elem );
                    len = name.length;

                    for ( ; i < len; i++ ) {
                        map[ name[ i ] ] = jquery.css( elem, name[ i ], false, styles );
                    }

                    return map;
                }

                return value !== undefined ?
                    jquery.style( elem, name, value ) :
                    jquery.css( elem, name );
            }, name, value, arguments.length > 1 );
        },
        show: function() {
            return showhide( this, true );
        },
        hide: function() {
            return showhide( this );
        },
        toggle: function( state ) {
            if ( typeof state === "boolean" ) {
                return state ? this.show() : this.hide();
            }

            return this.each(function() {
                if ( ishidden( this ) ) {
                    jquery( this ).show();
                } else {
                    jquery( this ).hide();
                }
            });
        }
    });

    jquery.extend({
        // add in style property hooks for overriding the default
        // behavior of getting and setting a style property
        csshooks: {
            opacity: {
                get: function( elem, computed ) {
                    if ( computed ) {
                        // we should always get a number back from opacity
                        var ret = curcss( elem, "opacity" );
                        return ret === "" ? "1" : ret;
                    }
                }
            }
        },

        // don't automatically add "px" to these possibly-unitless properties
        cssnumber: {
            "columncount": true,
            "fillopacity": true,
            "fontweight": true,
            "lineheight": true,
            "opacity": true,
            "order": true,
            "orphans": true,
            "widows": true,
            "zindex": true,
            "zoom": true
        },

        // add in properties whose names you wish to fix before
        // setting or getting the value
        cssprops: {
            // normalize float css property
            "float": jquery.support.cssfloat ? "cssfloat" : "stylefloat"
        },

        // get and set the style property on a dom node
        style: function( elem, name, value, extra ) {
            // don't set styles on text and comment nodes
            if ( !elem || elem.nodetype === 3 || elem.nodetype === 8 || !elem.style ) {
                return;
            }

            // make sure that we're working with the right name
            var ret, type, hooks,
                origname = jquery.camelcase( name ),
                style = elem.style;

            name = jquery.cssprops[ origname ] || ( jquery.cssprops[ origname ] = vendorpropname( style, origname ) );

            // gets hook for the prefixed version
            // followed by the unprefixed version
            hooks = jquery.csshooks[ name ] || jquery.csshooks[ origname ];

            // check if we're setting a value
            if ( value !== undefined ) {
                type = typeof value;

                // convert relative number strings (+= or -=) to relative numbers. #7345
                if ( type === "string" && (ret = rrelnum.exec( value )) ) {
                    value = ( ret[1] + 1 ) * ret[2] + parsefloat( jquery.css( elem, name ) );
                    // fixes bug #9237
                    type = "number";
                }

                // make sure that nan and null values aren't set. see: #7116
                if ( value == null || type === "number" && isnan( value ) ) {
                    return;
                }

                // if a number was passed in, add 'px' to the (except for certain css properties)
                if ( type === "number" && !jquery.cssnumber[ origname ] ) {
                    value += "px";
                }

                // fixes #8908, it can be done more correctly by specifing setters in csshooks,
                // but it would mean to define eight (for every problematic property) identical functions
                if ( !jquery.support.clearclonestyle && value === "" && name.indexof("background") === 0 ) {
                    style[ name ] = "inherit";
                }

                // if a hook was provided, use that value, otherwise just set the specified value
                if ( !hooks || !("set" in hooks) || (value = hooks.set( elem, value, extra )) !== undefined ) {

                    // wrapped to prevent ie from throwing errors when 'invalid' values are provided
                    // fixes bug #5509
                    try {
                        style[ name ] = value;
                    } catch(e) {}
                }

            } else {
                // if a hook was provided get the non-computed value from there
                if ( hooks && "get" in hooks && (ret = hooks.get( elem, false, extra )) !== undefined ) {
                    return ret;
                }

                // otherwise just get the value from the style object
                return style[ name ];
            }
        },

        css: function( elem, name, extra, styles ) {
            var num, val, hooks,
                origname = jquery.camelcase( name );

            // make sure that we're working with the right name
            name = jquery.cssprops[ origname ] || ( jquery.cssprops[ origname ] = vendorpropname( elem.style, origname ) );

            // gets hook for the prefixed version
            // followed by the unprefixed version
            hooks = jquery.csshooks[ name ] || jquery.csshooks[ origname ];

            // if a hook was provided get the computed value from there
            if ( hooks && "get" in hooks ) {
                val = hooks.get( elem, true, extra );
            }

            // otherwise, if a way to get the computed value exists, use that
            if ( val === undefined ) {
                val = curcss( elem, name, styles );
            }

            //convert "normal" to computed value
            if ( val === "normal" && name in cssnormaltransform ) {
                val = cssnormaltransform[ name ];
            }

            // return, converting to number if forced or a qualifier was provided and val looks numeric
            if ( extra === "" || extra ) {
                num = parsefloat( val );
                return extra === true || jquery.isnumeric( num ) ? num || 0 : val;
            }
            return val;
        }
    });

// note: we've included the "window" in window.getcomputedstyle
// because jsdom on node.js will break without it.
    if ( window.getcomputedstyle ) {
        getstyles = function( elem ) {
            return window.getcomputedstyle( elem, null );
        };

        curcss = function( elem, name, _computed ) {
            var width, minwidth, maxwidth,
                computed = _computed || getstyles( elem ),

            // getpropertyvalue is only needed for .css('filter') in ie9, see #12537
                ret = computed ? computed.getpropertyvalue( name ) || computed[ name ] : undefined,
                style = elem.style;

            if ( computed ) {

                if ( ret === "" && !jquery.contains( elem.ownerdocument, elem ) ) {
                    ret = jquery.style( elem, name );
                }

                // a tribute to the "awesome hack by dean edwards"
                // chrome < 17 and safari 5.0 uses "computed value" instead of "used value" for margin-right
                // safari 5.1.7 (at least) returns percentage for a larger set of values, but width seems to be reliably pixels
                // this is against the cssom draft spec: http://dev.w3.org/csswg/cssom/#resolved-values
                if ( rnumnonpx.test( ret ) && rmargin.test( name ) ) {

                    // remember the original values
                    width = style.width;
                    minwidth = style.minwidth;
                    maxwidth = style.maxwidth;

                    // put in the new values to get a computed value out
                    style.minwidth = style.maxwidth = style.width = ret;
                    ret = computed.width;

                    // revert the changed values
                    style.width = width;
                    style.minwidth = minwidth;
                    style.maxwidth = maxwidth;
                }
            }

            return ret;
        };
    } else if ( document.documentelement.currentstyle ) {
        getstyles = function( elem ) {
            return elem.currentstyle;
        };

        curcss = function( elem, name, _computed ) {
            var left, rs, rsleft,
                computed = _computed || getstyles( elem ),
                ret = computed ? computed[ name ] : undefined,
                style = elem.style;

            // avoid setting ret to empty string here
            // so we don't default to auto
            if ( ret == null && style && style[ name ] ) {
                ret = style[ name ];
            }

            // from the awesome hack by dean edwards
            // http://erik.eae.net/archives/2007/07/27/18.54.15/#comment-102291

            // if we're not dealing with a regular pixel number
            // but a number that has a weird ending, we need to convert it to pixels
            // but not position css attributes, as those are proportional to the parent element instead
            // and we can't measure the parent instead because it might trigger a "stacking dolls" problem
            if ( rnumnonpx.test( ret ) && !rposition.test( name ) ) {

                // remember the original values
                left = style.left;
                rs = elem.runtimestyle;
                rsleft = rs && rs.left;

                // put in the new values to get a computed value out
                if ( rsleft ) {
                    rs.left = elem.currentstyle.left;
                }
                style.left = name === "fontsize" ? "1em" : ret;
                ret = style.pixelleft + "px";

                // revert the changed values
                style.left = left;
                if ( rsleft ) {
                    rs.left = rsleft;
                }
            }

            return ret === "" ? "auto" : ret;
        };
    }

    function setpositivenumber( elem, value, subtract ) {
        var matches = rnumsplit.exec( value );
        return matches ?
            // guard against undefined "subtract", e.g., when used as in csshooks
            math.max( 0, matches[ 1 ] - ( subtract || 0 ) ) + ( matches[ 2 ] || "px" ) :
            value;
    }

    function augmentwidthorheight( elem, name, extra, isborderbox, styles ) {
        var i = extra === ( isborderbox ? "border" : "content" ) ?
                // if we already have the right measurement, avoid augmentation
                4 :
                // otherwise initialize for horizontal or vertical properties
                    name === "width" ? 1 : 0,

            val = 0;

        for ( ; i < 4; i += 2 ) {
            // both box models exclude margin, so add it if we want it
            if ( extra === "margin" ) {
                val += jquery.css( elem, extra + cssexpand[ i ], true, styles );
            }

            if ( isborderbox ) {
                // border-box includes padding, so remove it if we want content
                if ( extra === "content" ) {
                    val -= jquery.css( elem, "padding" + cssexpand[ i ], true, styles );
                }

                // at this point, extra isn't border nor margin, so remove border
                if ( extra !== "margin" ) {
                    val -= jquery.css( elem, "border" + cssexpand[ i ] + "width", true, styles );
                }
            } else {
                // at this point, extra isn't content, so add padding
                val += jquery.css( elem, "padding" + cssexpand[ i ], true, styles );

                // at this point, extra isn't content nor padding, so add border
                if ( extra !== "padding" ) {
                    val += jquery.css( elem, "border" + cssexpand[ i ] + "width", true, styles );
                }
            }
        }

        return val;
    }

    function getwidthorheight( elem, name, extra ) {

        // start with offset property, which is equivalent to the border-box value
        var valueisborderbox = true,
            val = name === "width" ? elem.offsetwidth : elem.offsetheight,
            styles = getstyles( elem ),
            isborderbox = jquery.support.boxsizing && jquery.css( elem, "boxsizing", false, styles ) === "border-box";

        // some non-html elements return undefined for offsetwidth, so check for null/undefined
        // svg - https://bugzilla.mozilla.org/show_bug.cgi?id=649285
        // mathml - https://bugzilla.mozilla.org/show_bug.cgi?id=491668
        if ( val <= 0 || val == null ) {
            // fall back to computed then uncomputed css if necessary
            val = curcss( elem, name, styles );
            if ( val < 0 || val == null ) {
                val = elem.style[ name ];
            }

            // computed unit is not pixels. stop here and return.
            if ( rnumnonpx.test(val) ) {
                return val;
            }

            // we need the check for style in case a browser which returns unreliable values
            // for getcomputedstyle silently falls back to the reliable elem.style
            valueisborderbox = isborderbox && ( jquery.support.boxsizingreliable || val === elem.style[ name ] );

            // normalize "", auto, and prepare for extra
            val = parsefloat( val ) || 0;
        }

        // use the active box-sizing model to add/subtract irrelevant styles
        return ( val +
            augmentwidthorheight(
                elem,
                name,
                    extra || ( isborderbox ? "border" : "content" ),
                valueisborderbox,
                styles
            )
            ) + "px";
    }

// try to determine the default display value of an element
    function css_defaultdisplay( nodename ) {
        var doc = document,
            display = elemdisplay[ nodename ];

        if ( !display ) {
            display = actualdisplay( nodename, doc );

            // if the simple way fails, read from inside an iframe
            if ( display === "none" || !display ) {
                // use the already-created iframe if possible
                iframe = ( iframe ||
                    jquery("<iframe frameborder='0' width='0' height='0'/>")
                        .css( "csstext", "display:block !important" )
                    ).appendto( doc.documentelement );

                // always write a new html skeleton so webkit and firefox don't choke on reuse
                doc = ( iframe[0].contentwindow || iframe[0].contentdocument ).document;
                doc.write("<!doctype html><html><body>");
                doc.close();

                display = actualdisplay( nodename, doc );
                iframe.detach();
            }

            // store the correct default display
            elemdisplay[ nodename ] = display;
        }

        return display;
    }

// called only from within css_defaultdisplay
    function actualdisplay( name, doc ) {
        var elem = jquery( doc.createelement( name ) ).appendto( doc.body ),
            display = jquery.css( elem[0], "display" );
        elem.remove();
        return display;
    }

    jquery.each([ "height", "width" ], function( i, name ) {
        jquery.csshooks[ name ] = {
            get: function( elem, computed, extra ) {
                if ( computed ) {
                    // certain elements can have dimension info if we invisibly show them
                    // however, it must have a current display style that would benefit from this
                    return elem.offsetwidth === 0 && rdisplayswap.test( jquery.css( elem, "display" ) ) ?
                        jquery.swap( elem, cssshow, function() {
                            return getwidthorheight( elem, name, extra );
                        }) :
                        getwidthorheight( elem, name, extra );
                }
            },

            set: function( elem, value, extra ) {
                var styles = extra && getstyles( elem );
                return setpositivenumber( elem, value, extra ?
                        augmentwidthorheight(
                            elem,
                            name,
                            extra,
                                jquery.support.boxsizing && jquery.css( elem, "boxsizing", false, styles ) === "border-box",
                            styles
                        ) : 0
                );
            }
        };
    });

    if ( !jquery.support.opacity ) {
        jquery.csshooks.opacity = {
            get: function( elem, computed ) {
                // ie uses filters for opacity
                return ropacity.test( (computed && elem.currentstyle ? elem.currentstyle.filter : elem.style.filter) || "" ) ?
                    ( 0.01 * parsefloat( regexp.$1 ) ) + "" :
                    computed ? "1" : "";
            },

            set: function( elem, value ) {
                var style = elem.style,
                    currentstyle = elem.currentstyle,
                    opacity = jquery.isnumeric( value ) ? "alpha(opacity=" + value * 100 + ")" : "",
                    filter = currentstyle && currentstyle.filter || style.filter || "";

                // ie has trouble with opacity if it does not have layout
                // force it by setting the zoom level
                style.zoom = 1;

                // if setting opacity to 1, and no other filters exist - attempt to remove filter attribute #6652
                // if value === "", then remove inline opacity #12685
                if ( ( value >= 1 || value === "" ) &&
                    jquery.trim( filter.replace( ralpha, "" ) ) === "" &&
                    style.removeattribute ) {

                    // setting style.filter to null, "" & " " still leave "filter:" in the csstext
                    // if "filter:" is present at all, cleartype is disabled, we want to avoid this
                    // style.removeattribute is ie only, but so apparently is this code path...
                    style.removeattribute( "filter" );

                    // if there is no filter style applied in a css rule or unset inline opacity, we are done
                    if ( value === "" || currentstyle && !currentstyle.filter ) {
                        return;
                    }
                }

                // otherwise, set new filter values
                style.filter = ralpha.test( filter ) ?
                    filter.replace( ralpha, opacity ) :
                    filter + " " + opacity;
            }
        };
    }

// these hooks cannot be added until dom ready because the support test
// for it is not run until after dom ready
    jquery(function() {
        if ( !jquery.support.reliablemarginright ) {
            jquery.csshooks.marginright = {
                get: function( elem, computed ) {
                    if ( computed ) {
                        // webkit bug 13343 - getcomputedstyle returns wrong value for margin-right
                        // work around by temporarily setting element display to inline-block
                        return jquery.swap( elem, { "display": "inline-block" },
                            curcss, [ elem, "marginright" ] );
                    }
                }
            };
        }

        // webkit bug: https://bugs.webkit.org/show_bug.cgi?id=29084
        // getcomputedstyle returns percent when specified for top/left/bottom/right
        // rather than make the css module depend on the offset module, we just check for it here
        if ( !jquery.support.pixelposition && jquery.fn.position ) {
            jquery.each( [ "top", "left" ], function( i, prop ) {
                jquery.csshooks[ prop ] = {
                    get: function( elem, computed ) {
                        if ( computed ) {
                            computed = curcss( elem, prop );
                            // if curcss returns percentage, fallback to offset
                            return rnumnonpx.test( computed ) ?
                                jquery( elem ).position()[ prop ] + "px" :
                                computed;
                        }
                    }
                };
            });
        }

    });

    if ( jquery.expr && jquery.expr.filters ) {
        jquery.expr.filters.hidden = function( elem ) {
            // support: opera <= 12.12
            // opera reports offsetwidths and offsetheights less than zero on some elements
            return elem.offsetwidth <= 0 && elem.offsetheight <= 0 ||
                (!jquery.support.reliablehiddenoffsets && ((elem.style && elem.style.display) || jquery.css( elem, "display" )) === "none");
        };

        jquery.expr.filters.visible = function( elem ) {
            return !jquery.expr.filters.hidden( elem );
        };
    }

// these hooks are used by animate to expand properties
    jquery.each({
        margin: "",
        padding: "",
        border: "width"
    }, function( prefix, suffix ) {
        jquery.csshooks[ prefix + suffix ] = {
            expand: function( value ) {
                var i = 0,
                    expanded = {},

                // assumes a single number if not a string
                    parts = typeof value === "string" ? value.split(" ") : [ value ];

                for ( ; i < 4; i++ ) {
                    expanded[ prefix + cssexpand[ i ] + suffix ] =
                        parts[ i ] || parts[ i - 2 ] || parts[ 0 ];
                }

                return expanded;
            }
        };

        if ( !rmargin.test( prefix ) ) {
            jquery.csshooks[ prefix + suffix ].set = setpositivenumber;
        }
    });
    var r20 = /%20/g,
        rbracket = /\[\]$/,
        rcrlf = /\r?\n/g,
        rsubmittertypes = /^(?:submit|button|image|reset|file)$/i,
        rsubmittable = /^(?:input|select|textarea|keygen)/i;

    jquery.fn.extend({
        serialize: function() {
            return jquery.param( this.serializearray() );
        },
        serializearray: function() {
            return this.map(function(){
                // can add prophook for "elements" to filter or add form elements
                var elements = jquery.prop( this, "elements" );
                return elements ? jquery.makearray( elements ) : this;
            })
                .filter(function(){
                    var type = this.type;
                    // use .is(":disabled") so that fieldset[disabled] works
                    return this.name && !jquery( this ).is( ":disabled" ) &&
                        rsubmittable.test( this.nodename ) && !rsubmittertypes.test( type ) &&
                        ( this.checked || !manipulation_rcheckabletype.test( type ) );
                })
                .map(function( i, elem ){
                    var val = jquery( this ).val();

                    return val == null ?
                        null :
                        jquery.isarray( val ) ?
                            jquery.map( val, function( val ){
                                return { name: elem.name, value: val.replace( rcrlf, "\r\n" ) };
                            }) :
                        { name: elem.name, value: val.replace( rcrlf, "\r\n" ) };
                }).get();
        }
    });

//serialize an array of form elements or a set of
//key/values into a query string
    jquery.param = function( a, traditional ) {
        var prefix,
            s = [],
            add = function( key, value ) {
                // if value is a function, invoke it and return its value
                value = jquery.isfunction( value ) ? value() : ( value == null ? "" : value );
                s[ s.length ] = encodeuricomponent( key ) + "=" + encodeuricomponent( value );
            };

        // set traditional to true for jquery <= 1.3.2 behavior.
        if ( traditional === undefined ) {
            traditional = jquery.ajaxsettings && jquery.ajaxsettings.traditional;
        }

        // if an array was passed in, assume that it is an array of form elements.
        if ( jquery.isarray( a ) || ( a.jquery && !jquery.isplainobject( a ) ) ) {
            // serialize the form elements
            jquery.each( a, function() {
                add( this.name, this.value );
            });

        } else {
            // if traditional, encode the "old" way (the way 1.3.2 or older
            // did it), otherwise encode params recursively.
            for ( prefix in a ) {
                buildparams( prefix, a[ prefix ], traditional, add );
            }
        }

        // return the resulting serialization
        return s.join( "&" ).replace( r20, "+" );
    };

    function buildparams( prefix, obj, traditional, add ) {
        var name;

        if ( jquery.isarray( obj ) ) {
            // serialize array item.
            jquery.each( obj, function( i, v ) {
                if ( traditional || rbracket.test( prefix ) ) {
                    // treat each array item as a scalar.
                    add( prefix, v );

                } else {
                    // item is non-scalar (array or object), encode its numeric index.
                    buildparams( prefix + "[" + ( typeof v === "object" ? i : "" ) + "]", v, traditional, add );
                }
            });

        } else if ( !traditional && jquery.type( obj ) === "object" ) {
            // serialize object item.
            for ( name in obj ) {
                buildparams( prefix + "[" + name + "]", obj[ name ], traditional, add );
            }

        } else {
            // serialize scalar item.
            add( prefix, obj );
        }
    }
    jquery.each( ("blur focus focusin focusout load resize scroll unload click dblclick " +
        "mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave " +
        "change select submit keydown keypress keyup error contextmenu").split(" "), function( i, name ) {

        // handle event binding
        jquery.fn[ name ] = function( data, fn ) {
            return arguments.length > 0 ?
                this.on( name, null, data, fn ) :
                this.trigger( name );
        };
    });

    jquery.fn.extend({
        hover: function( fnover, fnout ) {
            return this.mouseenter( fnover ).mouseleave( fnout || fnover );
        },

        bind: function( types, data, fn ) {
            return this.on( types, null, data, fn );
        },
        unbind: function( types, fn ) {
            return this.off( types, null, fn );
        },

        delegate: function( selector, types, data, fn ) {
            return this.on( types, selector, data, fn );
        },
        undelegate: function( selector, types, fn ) {
            // ( namespace ) or ( selector, types [, fn] )
            return arguments.length === 1 ? this.off( selector, "**" ) : this.off( types, selector || "**", fn );
        }
    });
    var
    // document location
        ajaxlocparts,
        ajaxlocation,
        ajax_nonce = jquery.now(),

        ajax_rquery = /\?/,
        rhash = /#.*$/,
        rts = /([?&])_=[^&]*/,
        rheaders = /^(.*?):[ \t]*([^\r\n]*)\r?$/mg, // ie leaves an \r character at eol
    // #7653, #8125, #8152: local protocol detection
        rlocalprotocol = /^(?:about|app|app-storage|.+-extension|file|res|widget):$/,
        rnocontent = /^(?:get|head)$/,
        rprotocol = /^\/\//,
        rurl = /^([\w.+-]+:)(?:\/\/([^\/?#:]*)(?::(\d+)|)|)/,

    // keep a copy of the old load method
        _load = jquery.fn.load,

    /* prefilters
     * 1) they are useful to introduce custom datatypes (see ajax/jsonp.js for an example)
     * 2) these are called:
     *    - before asking for a transport
     *    - after param serialization (s.data is a string if s.processdata is true)
     * 3) key is the datatype
     * 4) the catchall symbol "*" can be used
     * 5) execution will start with transport datatype and then continue down to "*" if needed
     */
        prefilters = {},

    /* transports bindings
     * 1) key is the datatype
     * 2) the catchall symbol "*" can be used
     * 3) selection will start with transport datatype and then go to "*" if needed
     */
        transports = {},

    // avoid comment-prolog char sequence (#10098); must appease lint and evade compression
        alltypes = "*/".concat("*");

// #8138, ie may throw an exception when accessing
// a field from window.location if document.domain has been set
    try {
        ajaxlocation = location.href;
    } catch( e ) {
        // use the href attribute of an a element
        // since ie will modify it given document.location
        ajaxlocation = document.createelement( "a" );
        ajaxlocation.href = "";
        ajaxlocation = ajaxlocation.href;
    }

// segment location into parts
    ajaxlocparts = rurl.exec( ajaxlocation.tolowercase() ) || [];

// base "constructor" for jquery.ajaxprefilter and jquery.ajaxtransport
    function addtoprefiltersortransports( structure ) {

        // datatypeexpression is optional and defaults to "*"
        return function( datatypeexpression, func ) {

            if ( typeof datatypeexpression !== "string" ) {
                func = datatypeexpression;
                datatypeexpression = "*";
            }

            var datatype,
                i = 0,
                datatypes = datatypeexpression.tolowercase().match( core_rnotwhite ) || [];

            if ( jquery.isfunction( func ) ) {
                // for each datatype in the datatypeexpression
                while ( (datatype = datatypes[i++]) ) {
                    // prepend if requested
                    if ( datatype[0] === "+" ) {
                        datatype = datatype.slice( 1 ) || "*";
                        (structure[ datatype ] = structure[ datatype ] || []).unshift( func );

                        // otherwise append
                    } else {
                        (structure[ datatype ] = structure[ datatype ] || []).push( func );
                    }
                }
            }
        };
    }

// base inspection function for prefilters and transports
    function inspectprefiltersortransports( structure, options, originaloptions, jqxhr ) {

        var inspected = {},
            seekingtransport = ( structure === transports );

        function inspect( datatype ) {
            var selected;
            inspected[ datatype ] = true;
            jquery.each( structure[ datatype ] || [], function( _, prefilterorfactory ) {
                var datatypeortransport = prefilterorfactory( options, originaloptions, jqxhr );
                if( typeof datatypeortransport === "string" && !seekingtransport && !inspected[ datatypeortransport ] ) {
                    options.datatypes.unshift( datatypeortransport );
                    inspect( datatypeortransport );
                    return false;
                } else if ( seekingtransport ) {
                    return !( selected = datatypeortransport );
                }
            });
            return selected;
        }

        return inspect( options.datatypes[ 0 ] ) || !inspected[ "*" ] && inspect( "*" );
    }

// a special extend for ajax options
// that takes "flat" options (not to be deep extended)
// fixes #9887
    function ajaxextend( target, src ) {
        var deep, key,
            flatoptions = jquery.ajaxsettings.flatoptions || {};

        for ( key in src ) {
            if ( src[ key ] !== undefined ) {
                ( flatoptions[ key ] ? target : ( deep || (deep = {}) ) )[ key ] = src[ key ];
            }
        }
        if ( deep ) {
            jquery.extend( true, target, deep );
        }

        return target;
    }

    jquery.fn.load = function( url, params, callback ) {
        if ( typeof url !== "string" && _load ) {
            return _load.apply( this, arguments );
        }

        var selector, response, type,
            self = this,
            off = url.indexof(" ");

        if ( off >= 0 ) {
            selector = url.slice( off, url.length );
            url = url.slice( 0, off );
        }

        // if it's a function
        if ( jquery.isfunction( params ) ) {

            // we assume that it's the callback
            callback = params;
            params = undefined;

            // otherwise, build a param string
        } else if ( params && typeof params === "object" ) {
            type = "post";
        }

        // if we have elements to modify, make the request
        if ( self.length > 0 ) {
            jquery.ajax({
                url: url,

                // if "type" variable is undefined, then "get" method will be used
                type: type,
                datatype: "html",
                data: params
            }).done(function( responsetext ) {

                // save response for use in complete callback
                response = arguments;

                self.html( selector ?

                    // if a selector was specified, locate the right elements in a dummy div
                    // exclude scripts to avoid ie 'permission denied' errors
                    jquery("<div>").append( jquery.parsehtml( responsetext ) ).find( selector ) :

                    // otherwise use the full result
                    responsetext );

            }).complete( callback && function( jqxhr, status ) {
                self.each( callback, response || [ jqxhr.responsetext, status, jqxhr ] );
            });
        }

        return this;
    };

// attach a bunch of functions for handling common ajax events
    jquery.each( [ "ajaxstart", "ajaxstop", "ajaxcomplete", "ajaxerror", "ajaxsuccess", "ajaxsend" ], function( i, type ){
        jquery.fn[ type ] = function( fn ){
            return this.on( type, fn );
        };
    });

    jquery.extend({

        // counter for holding the number of active queries
        active: 0,

        // last-modified header cache for next request
        lastmodified: {},
        etag: {},

        ajaxsettings: {
            url: ajaxlocation,
            type: "get",
            islocal: rlocalprotocol.test( ajaxlocparts[ 1 ] ),
            global: true,
            processdata: true,
            async: true,
            contenttype: "application/x-www-form-urlencoded; charset=utf-8",
            /*
             timeout: 0,
             data: null,
             datatype: null,
             username: null,
             password: null,
             cache: null,
             throws: false,
             traditional: false,
             headers: {},
             */

            accepts: {
                "*": alltypes,
                text: "text/plain",
                html: "text/html",
                xml: "application/xml, text/xml",
                json: "application/json, text/javascript"
            },

            contents: {
                xml: /xml/,
                html: /html/,
                json: /json/
            },

            responsefields: {
                xml: "responsexml",
                text: "responsetext",
                json: "responsejson"
            },

            // data converters
            // keys separate source (or catchall "*") and destination types with a single space
            converters: {

                // convert anything to text
                "* text": string,

                // text to html (true = no transformation)
                "text html": true,

                // evaluate text as a json expression
                "text json": jquery.parsejson,

                // parse text as xml
                "text xml": jquery.parsexml
            },

            // for options that shouldn't be deep extended:
            // you can add your own custom options here if
            // and when you create one that shouldn't be
            // deep extended (see ajaxextend)
            flatoptions: {
                url: true,
                context: true
            }
        },

        // creates a full fledged settings object into target
        // with both ajaxsettings and settings fields.
        // if target is omitted, writes into ajaxsettings.
        ajaxsetup: function( target, settings ) {
            return settings ?

                // building a settings object
                ajaxextend( ajaxextend( target, jquery.ajaxsettings ), settings ) :

                // extending ajaxsettings
                ajaxextend( jquery.ajaxsettings, target );
        },

        ajaxprefilter: addtoprefiltersortransports( prefilters ),
        ajaxtransport: addtoprefiltersortransports( transports ),

        // main method
        ajax: function( url, options ) {

            // if url is an object, simulate pre-1.5 signature
            if ( typeof url === "object" ) {
                options = url;
                url = undefined;
            }

            // force options to be an object
            options = options || {};

            var // cross-domain detection vars
                parts,
            // loop variable
                i,
            // url without anti-cache param
                cacheurl,
            // response headers as string
                responseheadersstring,
            // timeout handle
                timeouttimer,

            // to know if global events are to be dispatched
                fireglobals,

                transport,
            // response headers
                responseheaders,
            // create the final options object
                s = jquery.ajaxsetup( {}, options ),
            // callbacks context
                callbackcontext = s.context || s,
            // context for global events is callbackcontext if it is a dom node or jquery collection
                globaleventcontext = s.context && ( callbackcontext.nodetype || callbackcontext.jquery ) ?
                    jquery( callbackcontext ) :
                    jquery.event,
            // deferreds
                deferred = jquery.deferred(),
                completedeferred = jquery.callbacks("once memory"),
            // status-dependent callbacks
                statuscode = s.statuscode || {},
            // headers (they are sent all at once)
                requestheaders = {},
                requestheadersnames = {},
            // the jqxhr state
                state = 0,
            // default abort message
                strabort = "canceled",
            // fake xhr
                jqxhr = {
                    readystate: 0,

                    // builds headers hashtable if needed
                    getresponseheader: function( key ) {
                        var match;
                        if ( state === 2 ) {
                            if ( !responseheaders ) {
                                responseheaders = {};
                                while ( (match = rheaders.exec( responseheadersstring )) ) {
                                    responseheaders[ match[1].tolowercase() ] = match[ 2 ];
                                }
                            }
                            match = responseheaders[ key.tolowercase() ];
                        }
                        return match == null ? null : match;
                    },

                    // raw string
                    getallresponseheaders: function() {
                        return state === 2 ? responseheadersstring : null;
                    },

                    // caches the header
                    setrequestheader: function( name, value ) {
                        var lname = name.tolowercase();
                        if ( !state ) {
                            name = requestheadersnames[ lname ] = requestheadersnames[ lname ] || name;
                            requestheaders[ name ] = value;
                        }
                        return this;
                    },

                    // overrides response content-type header
                    overridemimetype: function( type ) {
                        if ( !state ) {
                            s.mimetype = type;
                        }
                        return this;
                    },

                    // status-dependent callbacks
                    statuscode: function( map ) {
                        var code;
                        if ( map ) {
                            if ( state < 2 ) {
                                for ( code in map ) {
                                    // lazy-add the new callback in a way that preserves old ones
                                    statuscode[ code ] = [ statuscode[ code ], map[ code ] ];
                                }
                            } else {
                                // execute the appropriate callbacks
                                jqxhr.always( map[ jqxhr.status ] );
                            }
                        }
                        return this;
                    },

                    // cancel the request
                    abort: function( statustext ) {
                        var finaltext = statustext || strabort;
                        if ( transport ) {
                            transport.abort( finaltext );
                        }
                        done( 0, finaltext );
                        return this;
                    }
                };

            // attach deferreds
            deferred.promise( jqxhr ).complete = completedeferred.add;
            jqxhr.success = jqxhr.done;
            jqxhr.error = jqxhr.fail;

            // remove hash character (#7531: and string promotion)
            // add protocol if not provided (#5866: ie7 issue with protocol-less urls)
            // handle falsy url in the settings object (#10093: consistency with old signature)
            // we also use the url parameter if available
            s.url = ( ( url || s.url || ajaxlocation ) + "" ).replace( rhash, "" ).replace( rprotocol, ajaxlocparts[ 1 ] + "//" );

            // alias method option to type as per ticket #12004
            s.type = options.method || options.type || s.method || s.type;

            // extract datatypes list
            s.datatypes = jquery.trim( s.datatype || "*" ).tolowercase().match( core_rnotwhite ) || [""];

            // a cross-domain request is in order when we have a protocol:host:port mismatch
            if ( s.crossdomain == null ) {
                parts = rurl.exec( s.url.tolowercase() );
                s.crossdomain = !!( parts &&
                    ( parts[ 1 ] !== ajaxlocparts[ 1 ] || parts[ 2 ] !== ajaxlocparts[ 2 ] ||
                        ( parts[ 3 ] || ( parts[ 1 ] === "http:" ? "80" : "443" ) ) !==
                        ( ajaxlocparts[ 3 ] || ( ajaxlocparts[ 1 ] === "http:" ? "80" : "443" ) ) )
                    );
            }

            // convert data if not already a string
            if ( s.data && s.processdata && typeof s.data !== "string" ) {
                s.data = jquery.param( s.data, s.traditional );
            }

            // apply prefilters
            inspectprefiltersortransports( prefilters, s, options, jqxhr );

            // if request was aborted inside a prefilter, stop there
            if ( state === 2 ) {
                return jqxhr;
            }

            // we can fire global events as of now if asked to
            fireglobals = s.global;

            // watch for a new set of requests
            if ( fireglobals && jquery.active++ === 0 ) {
                jquery.event.trigger("ajaxstart");
            }

            // uppercase the type
            s.type = s.type.touppercase();

            // determine if request has content
            s.hascontent = !rnocontent.test( s.type );

            // save the url in case we're toying with the if-modified-since
            // and/or if-none-match header later on
            cacheurl = s.url;

            // more options handling for requests with no content
            if ( !s.hascontent ) {

                // if data is available, append data to url
                if ( s.data ) {
                    cacheurl = ( s.url += ( ajax_rquery.test( cacheurl ) ? "&" : "?" ) + s.data );
                    // #9682: remove data so that it's not used in an eventual retry
                    delete s.data;
                }

                // add anti-cache in url if needed
                if ( s.cache === false ) {
                    s.url = rts.test( cacheurl ) ?

                        // if there is already a '_' parameter, set its value
                        cacheurl.replace( rts, "$1_=" + ajax_nonce++ ) :

                        // otherwise add one to the end
                        cacheurl + ( ajax_rquery.test( cacheurl ) ? "&" : "?" ) + "_=" + ajax_nonce++;
                }
            }

            // set the if-modified-since and/or if-none-match header, if in ifmodified mode.
            if ( s.ifmodified ) {
                if ( jquery.lastmodified[ cacheurl ] ) {
                    jqxhr.setrequestheader( "if-modified-since", jquery.lastmodified[ cacheurl ] );
                }
                if ( jquery.etag[ cacheurl ] ) {
                    jqxhr.setrequestheader( "if-none-match", jquery.etag[ cacheurl ] );
                }
            }

            // set the correct header, if data is being sent
            if ( s.data && s.hascontent && s.contenttype !== false || options.contenttype ) {
                jqxhr.setrequestheader( "content-type", s.contenttype );
            }

            // set the accepts header for the server, depending on the datatype
            jqxhr.setrequestheader(
                "accept",
                    s.datatypes[ 0 ] && s.accepts[ s.datatypes[0] ] ?
                    s.accepts[ s.datatypes[0] ] + ( s.datatypes[ 0 ] !== "*" ? ", " + alltypes + "; q=0.01" : "" ) :
                    s.accepts[ "*" ]
            );

            // check for headers option
            for ( i in s.headers ) {
                jqxhr.setrequestheader( i, s.headers[ i ] );
            }

            // allow custom headers/mimetypes and early abort
            if ( s.beforesend && ( s.beforesend.call( callbackcontext, jqxhr, s ) === false || state === 2 ) ) {
                // abort if not done already and return
                return jqxhr.abort();
            }

            // aborting is no longer a cancellation
            strabort = "abort";

            // install callbacks on deferreds
            for ( i in { success: 1, error: 1, complete: 1 } ) {
                jqxhr[ i ]( s[ i ] );
            }

            // get transport
            transport = inspectprefiltersortransports( transports, s, options, jqxhr );

            // if no transport, we auto-abort
            if ( !transport ) {
                done( -1, "no transport" );
            } else {
                jqxhr.readystate = 1;

                // send global event
                if ( fireglobals ) {
                    globaleventcontext.trigger( "ajaxsend", [ jqxhr, s ] );
                }
                // timeout
                if ( s.async && s.timeout > 0 ) {
                    timeouttimer = settimeout(function() {
                        jqxhr.abort("timeout");
                    }, s.timeout );
                }

                try {
                    state = 1;
                    transport.send( requestheaders, done );
                } catch ( e ) {
                    // propagate exception as error if not done
                    if ( state < 2 ) {
                        done( -1, e );
                        // simply rethrow otherwise
                    } else {
                        throw e;
                    }
                }
            }

            // callback for when everything is done
            function done( status, nativestatustext, responses, headers ) {
                var issuccess, success, error, response, modified,
                    statustext = nativestatustext;

                // called once
                if ( state === 2 ) {
                    return;
                }

                // state is "done" now
                state = 2;

                // clear timeout if it exists
                if ( timeouttimer ) {
                    cleartimeout( timeouttimer );
                }

                // dereference transport for early garbage collection
                // (no matter how long the jqxhr object will be used)
                transport = undefined;

                // cache response headers
                responseheadersstring = headers || "";

                // set readystate
                jqxhr.readystate = status > 0 ? 4 : 0;

                // determine if successful
                issuccess = status >= 200 && status < 300 || status === 304;

                // get response data
                if ( responses ) {
                    response = ajaxhandleresponses( s, jqxhr, responses );
                }

                // convert no matter what (that way responsexxx fields are always set)
                response = ajaxconvert( s, response, jqxhr, issuccess );

                // if successful, handle type chaining
                if ( issuccess ) {

                    // set the if-modified-since and/or if-none-match header, if in ifmodified mode.
                    if ( s.ifmodified ) {
                        modified = jqxhr.getresponseheader("last-modified");
                        if ( modified ) {
                            jquery.lastmodified[ cacheurl ] = modified;
                        }
                        modified = jqxhr.getresponseheader("etag");
                        if ( modified ) {
                            jquery.etag[ cacheurl ] = modified;
                        }
                    }

                    // if no content
                    if ( status === 204 || s.type === "head" ) {
                        statustext = "nocontent";

                        // if not modified
                    } else if ( status === 304 ) {
                        statustext = "notmodified";

                        // if we have data, let's convert it
                    } else {
                        statustext = response.state;
                        success = response.data;
                        error = response.error;
                        issuccess = !error;
                    }
                } else {
                    // we extract error from statustext
                    // then normalize statustext and status for non-aborts
                    error = statustext;
                    if ( status || !statustext ) {
                        statustext = "error";
                        if ( status < 0 ) {
                            status = 0;
                        }
                    }
                }

                // set data for the fake xhr object
                jqxhr.status = status;
                jqxhr.statustext = ( nativestatustext || statustext ) + "";

                // success/error
                if ( issuccess ) {
                    deferred.resolvewith( callbackcontext, [ success, statustext, jqxhr ] );
                } else {
                    deferred.rejectwith( callbackcontext, [ jqxhr, statustext, error ] );
                }

                // status-dependent callbacks
                jqxhr.statuscode( statuscode );
                statuscode = undefined;

                if ( fireglobals ) {
                    globaleventcontext.trigger( issuccess ? "ajaxsuccess" : "ajaxerror",
                        [ jqxhr, s, issuccess ? success : error ] );
                }

                // complete
                completedeferred.firewith( callbackcontext, [ jqxhr, statustext ] );

                if ( fireglobals ) {
                    globaleventcontext.trigger( "ajaxcomplete", [ jqxhr, s ] );
                    // handle the global ajax counter
                    if ( !( --jquery.active ) ) {
                        jquery.event.trigger("ajaxstop");
                    }
                }
            }

            return jqxhr;
        },

        getjson: function( url, data, callback ) {
            return jquery.get( url, data, callback, "json" );
        },

        getscript: function( url, callback ) {
            return jquery.get( url, undefined, callback, "script" );
        }
    });

    jquery.each( [ "get", "post" ], function( i, method ) {
        jquery[ method ] = function( url, data, callback, type ) {
            // shift arguments if data argument was omitted
            if ( jquery.isfunction( data ) ) {
                type = type || callback;
                callback = data;
                data = undefined;
            }

            return jquery.ajax({
                url: url,
                type: method,
                datatype: type,
                data: data,
                success: callback
            });
        };
    });

    /* handles responses to an ajax request:
     * - finds the right datatype (mediates between content-type and expected datatype)
     * - returns the corresponding response
     */
    function ajaxhandleresponses( s, jqxhr, responses ) {
        var firstdatatype, ct, finaldatatype, type,
            contents = s.contents,
            datatypes = s.datatypes;

        // remove auto datatype and get content-type in the process
        while( datatypes[ 0 ] === "*" ) {
            datatypes.shift();
            if ( ct === undefined ) {
                ct = s.mimetype || jqxhr.getresponseheader("content-type");
            }
        }

        // check if we're dealing with a known content-type
        if ( ct ) {
            for ( type in contents ) {
                if ( contents[ type ] && contents[ type ].test( ct ) ) {
                    datatypes.unshift( type );
                    break;
                }
            }
        }

        // check to see if we have a response for the expected datatype
        if ( datatypes[ 0 ] in responses ) {
            finaldatatype = datatypes[ 0 ];
        } else {
            // try convertible datatypes
            for ( type in responses ) {
                if ( !datatypes[ 0 ] || s.converters[ type + " " + datatypes[0] ] ) {
                    finaldatatype = type;
                    break;
                }
                if ( !firstdatatype ) {
                    firstdatatype = type;
                }
            }
            // or just use first one
            finaldatatype = finaldatatype || firstdatatype;
        }

        // if we found a datatype
        // we add the datatype to the list if needed
        // and return the corresponding response
        if ( finaldatatype ) {
            if ( finaldatatype !== datatypes[ 0 ] ) {
                datatypes.unshift( finaldatatype );
            }
            return responses[ finaldatatype ];
        }
    }

    /* chain conversions given the request and the original response
     * also sets the responsexxx fields on the jqxhr instance
     */
    function ajaxconvert( s, response, jqxhr, issuccess ) {
        var conv2, current, conv, tmp, prev,
            converters = {},
        // work with a copy of datatypes in case we need to modify it for conversion
            datatypes = s.datatypes.slice();

        // create converters map with lowercased keys
        if ( datatypes[ 1 ] ) {
            for ( conv in s.converters ) {
                converters[ conv.tolowercase() ] = s.converters[ conv ];
            }
        }

        current = datatypes.shift();

        // convert to each sequential datatype
        while ( current ) {

            if ( s.responsefields[ current ] ) {
                jqxhr[ s.responsefields[ current ] ] = response;
            }

            // apply the datafilter if provided
            if ( !prev && issuccess && s.datafilter ) {
                response = s.datafilter( response, s.datatype );
            }

            prev = current;
            current = datatypes.shift();

            if ( current ) {

                // there's only work to do if current datatype is non-auto
                if ( current === "*" ) {

                    current = prev;

                    // convert response if prev datatype is non-auto and differs from current
                } else if ( prev !== "*" && prev !== current ) {

                    // seek a direct converter
                    conv = converters[ prev + " " + current ] || converters[ "* " + current ];

                    // if none found, seek a pair
                    if ( !conv ) {
                        for ( conv2 in converters ) {

                            // if conv2 outputs current
                            tmp = conv2.split( " " );
                            if ( tmp[ 1 ] === current ) {

                                // if prev can be converted to accepted input
                                conv = converters[ prev + " " + tmp[ 0 ] ] ||
                                    converters[ "* " + tmp[ 0 ] ];
                                if ( conv ) {
                                    // condense equivalence converters
                                    if ( conv === true ) {
                                        conv = converters[ conv2 ];

                                        // otherwise, insert the intermediate datatype
                                    } else if ( converters[ conv2 ] !== true ) {
                                        current = tmp[ 0 ];
                                        datatypes.unshift( tmp[ 1 ] );
                                    }
                                    break;
                                }
                            }
                        }
                    }

                    // apply converter (if not an equivalence)
                    if ( conv !== true ) {

                        // unless errors are allowed to bubble, catch and return them
                        if ( conv && s[ "throws" ] ) {
                            response = conv( response );
                        } else {
                            try {
                                response = conv( response );
                            } catch ( e ) {
                                return { state: "parsererror", error: conv ? e : "no conversion from " + prev + " to " + current };
                            }
                        }
                    }
                }
            }
        }

        return { state: "success", data: response };
    }
// install script datatype
    jquery.ajaxsetup({
        accepts: {
            script: "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript"
        },
        contents: {
            script: /(?:java|ecma)script/
        },
        converters: {
            "text script": function( text ) {
                jquery.globaleval( text );
                return text;
            }
        }
    });

// handle cache's special case and global
    jquery.ajaxprefilter( "script", function( s ) {
        if ( s.cache === undefined ) {
            s.cache = false;
        }
        if ( s.crossdomain ) {
            s.type = "get";
            s.global = false;
        }
    });

// bind script tag hack transport
    jquery.ajaxtransport( "script", function(s) {

        // this transport only deals with cross domain requests
        if ( s.crossdomain ) {

            var script,
                head = document.head || jquery("head")[0] || document.documentelement;

            return {

                send: function( _, callback ) {

                    script = document.createelement("script");

                    script.async = true;

                    if ( s.scriptcharset ) {
                        script.charset = s.scriptcharset;
                    }

                    script.src = s.url;

                    // attach handlers for all browsers
                    script.onload = script.onreadystatechange = function( _, isabort ) {

                        if ( isabort || !script.readystate || /loaded|complete/.test( script.readystate ) ) {

                            // handle memory leak in ie
                            script.onload = script.onreadystatechange = null;

                            // remove the script
                            if ( script.parentnode ) {
                                script.parentnode.removechild( script );
                            }

                            // dereference the script
                            script = null;

                            // callback if not abort
                            if ( !isabort ) {
                                callback( 200, "success" );
                            }
                        }
                    };

                    // circumvent ie6 bugs with base elements (#2709 and #4378) by prepending
                    // use native dom manipulation to avoid our dommanip ajax trickery
                    head.insertbefore( script, head.firstchild );
                },

                abort: function() {
                    if ( script ) {
                        script.onload( undefined, true );
                    }
                }
            };
        }
    });
    var oldcallbacks = [],
        rjsonp = /(=)\?(?=&|$)|\?\?/;

// default jsonp settings
    jquery.ajaxsetup({
        jsonp: "callback",
        jsonpcallback: function() {
            var callback = oldcallbacks.pop() || ( jquery.expando + "_" + ( ajax_nonce++ ) );
            this[ callback ] = true;
            return callback;
        }
    });

// detect, normalize options and install callbacks for jsonp requests
    jquery.ajaxprefilter( "json jsonp", function( s, originalsettings, jqxhr ) {

        var callbackname, overwritten, responsecontainer,
            jsonprop = s.jsonp !== false && ( rjsonp.test( s.url ) ?
                "url" :
                typeof s.data === "string" && !( s.contenttype || "" ).indexof("application/x-www-form-urlencoded") && rjsonp.test( s.data ) && "data"
                );

        // handle iff the expected data type is "jsonp" or we have a parameter to set
        if ( jsonprop || s.datatypes[ 0 ] === "jsonp" ) {

            // get callback name, remembering preexisting value associated with it
            callbackname = s.jsonpcallback = jquery.isfunction( s.jsonpcallback ) ?
                s.jsonpcallback() :
                s.jsonpcallback;

            // insert callback into url or form data
            if ( jsonprop ) {
                s[ jsonprop ] = s[ jsonprop ].replace( rjsonp, "$1" + callbackname );
            } else if ( s.jsonp !== false ) {
                s.url += ( ajax_rquery.test( s.url ) ? "&" : "?" ) + s.jsonp + "=" + callbackname;
            }

            // use data converter to retrieve json after script execution
            s.converters["script json"] = function() {
                if ( !responsecontainer ) {
                    jquery.error( callbackname + " was not called" );
                }
                return responsecontainer[ 0 ];
            };

            // force json datatype
            s.datatypes[ 0 ] = "json";

            // install callback
            overwritten = window[ callbackname ];
            window[ callbackname ] = function() {
                responsecontainer = arguments;
            };

            // clean-up function (fires after converters)
            jqxhr.always(function() {
                // restore preexisting value
                window[ callbackname ] = overwritten;

                // save back as free
                if ( s[ callbackname ] ) {
                    // make sure that re-using the options doesn't screw things around
                    s.jsonpcallback = originalsettings.jsonpcallback;

                    // save the callback name for future use
                    oldcallbacks.push( callbackname );
                }

                // call if it was a function and we have a response
                if ( responsecontainer && jquery.isfunction( overwritten ) ) {
                    overwritten( responsecontainer[ 0 ] );
                }

                responsecontainer = overwritten = undefined;
            });

            // delegate to script
            return "script";
        }
    });
    var xhrcallbacks, xhrsupported,
        xhrid = 0,
    // #5280: internet explorer will keep connections alive if we don't abort on unload
        xhronunloadabort = window.activexobject && function() {
            // abort all pending requests
            var key;
            for ( key in xhrcallbacks ) {
                xhrcallbacks[ key ]( undefined, true );
            }
        };

// functions to create xhrs
    function createstandardxhr() {
        try {
            return new window.xmlhttprequest();
        } catch( e ) {}
    }

    function createactivexhr() {
        try {
            return new window.activexobject("microsoft.xmlhttp");
        } catch( e ) {}
    }

// create the request object
// (this is still attached to ajaxsettings for backward compatibility)
    jquery.ajaxsettings.xhr = window.activexobject ?
        /* microsoft failed to properly
         * implement the xmlhttprequest in ie7 (can't request local files),
         * so we use the activexobject when it is available
         * additionally xmlhttprequest can be disabled in ie7/ie8 so
         * we need a fallback.
         */
        function() {
            return !this.islocal && createstandardxhr() || createactivexhr();
        } :
        // for all other browsers, use the standard xmlhttprequest object
        createstandardxhr;

// determine support properties
    xhrsupported = jquery.ajaxsettings.xhr();
    jquery.support.cors = !!xhrsupported && ( "withcredentials" in xhrsupported );
    xhrsupported = jquery.support.ajax = !!xhrsupported;

// create transport if the browser can provide an xhr
    if ( xhrsupported ) {

        jquery.ajaxtransport(function( s ) {
            // cross domain only allowed if supported through xmlhttprequest
            if ( !s.crossdomain || jquery.support.cors ) {

                var callback;

                return {
                    send: function( headers, complete ) {

                        // get a new xhr
                        var handle, i,
                            xhr = s.xhr();

                        // open the socket
                        // passing null username, generates a login popup on opera (#2865)
                        if ( s.username ) {
                            xhr.open( s.type, s.url, s.async, s.username, s.password );
                        } else {
                            xhr.open( s.type, s.url, s.async );
                        }

                        // apply custom fields if provided
                        if ( s.xhrfields ) {
                            for ( i in s.xhrfields ) {
                                xhr[ i ] = s.xhrfields[ i ];
                            }
                        }

                        // override mime type if needed
                        if ( s.mimetype && xhr.overridemimetype ) {
                            xhr.overridemimetype( s.mimetype );
                        }

                        // x-requested-with header
                        // for cross-domain requests, seeing as conditions for a preflight are
                        // akin to a jigsaw puzzle, we simply never set it to be sure.
                        // (it can always be set on a per-request basis or even using ajaxsetup)
                        // for same-domain requests, won't change header if already provided.
                        if ( !s.crossdomain && !headers["x-requested-with"] ) {
                            headers["x-requested-with"] = "xmlhttprequest";
                        }

                        // need an extra try/catch for cross domain requests in firefox 3
                        try {
                            for ( i in headers ) {
                                xhr.setrequestheader( i, headers[ i ] );
                            }
                        } catch( err ) {}

                        // do send the request
                        // this may raise an exception which is actually
                        // handled in jquery.ajax (so no try/catch here)
                        xhr.send( ( s.hascontent && s.data ) || null );

                        // listener
                        callback = function( _, isabort ) {
                            var status, responseheaders, statustext, responses;

                            // firefox throws exceptions when accessing properties
                            // of an xhr when a network error occurred
                            // http://helpful.knobs-dials.com/index.php/component_returned_failure_code:_0x80040111_(ns_error_not_available)
                            try {

                                // was never called and is aborted or complete
                                if ( callback && ( isabort || xhr.readystate === 4 ) ) {

                                    // only called once
                                    callback = undefined;

                                    // do not keep as active anymore
                                    if ( handle ) {
                                        xhr.onreadystatechange = jquery.noop;
                                        if ( xhronunloadabort ) {
                                            delete xhrcallbacks[ handle ];
                                        }
                                    }

                                    // if it's an abort
                                    if ( isabort ) {
                                        // abort it manually if needed
                                        if ( xhr.readystate !== 4 ) {
                                            xhr.abort();
                                        }
                                    } else {
                                        responses = {};
                                        status = xhr.status;
                                        responseheaders = xhr.getallresponseheaders();

                                        // when requesting binary data, ie6-9 will throw an exception
                                        // on any attempt to access responsetext (#11426)
                                        if ( typeof xhr.responsetext === "string" ) {
                                            responses.text = xhr.responsetext;
                                        }

                                        // firefox throws an exception when accessing
                                        // statustext for faulty cross-domain requests
                                        try {
                                            statustext = xhr.statustext;
                                        } catch( e ) {
                                            // we normalize with webkit giving an empty statustext
                                            statustext = "";
                                        }

                                        // filter status for non standard behaviors

                                        // if the request is local and we have data: assume a success
                                        // (success with no data won't get notified, that's the best we
                                        // can do given current implementations)
                                        if ( !status && s.islocal && !s.crossdomain ) {
                                            status = responses.text ? 200 : 404;
                                            // ie - #1450: sometimes returns 1223 when it should be 204
                                        } else if ( status === 1223 ) {
                                            status = 204;
                                        }
                                    }
                                }
                            } catch( firefoxaccessexception ) {
                                if ( !isabort ) {
                                    complete( -1, firefoxaccessexception );
                                }
                            }

                            // call complete if needed
                            if ( responses ) {
                                complete( status, statustext, responses, responseheaders );
                            }
                        };

                        if ( !s.async ) {
                            // if we're in sync mode we fire the callback
                            callback();
                        } else if ( xhr.readystate === 4 ) {
                            // (ie6 & ie7) if it's in cache and has been
                            // retrieved directly we need to fire the callback
                            settimeout( callback );
                        } else {
                            handle = ++xhrid;
                            if ( xhronunloadabort ) {
                                // create the active xhrs callbacks list if needed
                                // and attach the unload handler
                                if ( !xhrcallbacks ) {
                                    xhrcallbacks = {};
                                    jquery( window ).unload( xhronunloadabort );
                                }
                                // add to list of active xhrs callbacks
                                xhrcallbacks[ handle ] = callback;
                            }
                            xhr.onreadystatechange = callback;
                        }
                    },

                    abort: function() {
                        if ( callback ) {
                            callback( undefined, true );
                        }
                    }
                };
            }
        });
    }
    var fxnow, timerid,
        rfxtypes = /^(?:toggle|show|hide)$/,
        rfxnum = new regexp( "^(?:([+-])=|)(" + core_pnum + ")([a-z%]*)$", "i" ),
        rrun = /queuehooks$/,
        animationprefilters = [ defaultprefilter ],
        tweeners = {
            "*": [function( prop, value ) {
                var tween = this.createtween( prop, value ),
                    target = tween.cur(),
                    parts = rfxnum.exec( value ),
                    unit = parts && parts[ 3 ] || ( jquery.cssnumber[ prop ] ? "" : "px" ),

                // starting value computation is required for potential unit mismatches
                    start = ( jquery.cssnumber[ prop ] || unit !== "px" && +target ) &&
                        rfxnum.exec( jquery.css( tween.elem, prop ) ),
                    scale = 1,
                    maxiterations = 20;

                if ( start && start[ 3 ] !== unit ) {
                    // trust units reported by jquery.css
                    unit = unit || start[ 3 ];

                    // make sure we update the tween properties later on
                    parts = parts || [];

                    // iteratively approximate from a nonzero starting point
                    start = +target || 1;

                    do {
                        // if previous iteration zeroed out, double until we get *something*
                        // use a string for doubling factor so we don't accidentally see scale as unchanged below
                        scale = scale || ".5";

                        // adjust and apply
                        start = start / scale;
                        jquery.style( tween.elem, prop, start + unit );

                        // update scale, tolerating zero or nan from tween.cur()
                        // and breaking the loop if scale is unchanged or perfect, or if we've just had enough
                    } while ( scale !== (scale = tween.cur() / target) && scale !== 1 && --maxiterations );
                }

                // update tween properties
                if ( parts ) {
                    start = tween.start = +start || +target || 0;
                    tween.unit = unit;
                    // if a +=/-= token was provided, we're doing a relative animation
                    tween.end = parts[ 1 ] ?
                        start + ( parts[ 1 ] + 1 ) * parts[ 2 ] :
                        +parts[ 2 ];
                }

                return tween;
            }]
        };

// animations created synchronously will run synchronously
    function createfxnow() {
        settimeout(function() {
            fxnow = undefined;
        });
        return ( fxnow = jquery.now() );
    }

    function createtween( value, prop, animation ) {
        var tween,
            collection = ( tweeners[ prop ] || [] ).concat( tweeners[ "*" ] ),
            index = 0,
            length = collection.length;
        for ( ; index < length; index++ ) {
            if ( (tween = collection[ index ].call( animation, prop, value )) ) {

                // we're done with this property
                return tween;
            }
        }
    }

    function animation( elem, properties, options ) {
        var result,
            stopped,
            index = 0,
            length = animationprefilters.length,
            deferred = jquery.deferred().always( function() {
                // don't match elem in the :animated selector
                delete tick.elem;
            }),
            tick = function() {
                if ( stopped ) {
                    return false;
                }
                var currenttime = fxnow || createfxnow(),
                    remaining = math.max( 0, animation.starttime + animation.duration - currenttime ),
                // archaic crash bug won't allow us to use 1 - ( 0.5 || 0 ) (#12497)
                    temp = remaining / animation.duration || 0,
                    percent = 1 - temp,
                    index = 0,
                    length = animation.tweens.length;

                for ( ; index < length ; index++ ) {
                    animation.tweens[ index ].run( percent );
                }

                deferred.notifywith( elem, [ animation, percent, remaining ]);

                if ( percent < 1 && length ) {
                    return remaining;
                } else {
                    deferred.resolvewith( elem, [ animation ] );
                    return false;
                }
            },
            animation = deferred.promise({
                elem: elem,
                props: jquery.extend( {}, properties ),
                opts: jquery.extend( true, { specialeasing: {} }, options ),
                originalproperties: properties,
                originaloptions: options,
                starttime: fxnow || createfxnow(),
                duration: options.duration,
                tweens: [],
                createtween: function( prop, end ) {
                    var tween = jquery.tween( elem, animation.opts, prop, end,
                            animation.opts.specialeasing[ prop ] || animation.opts.easing );
                    animation.tweens.push( tween );
                    return tween;
                },
                stop: function( gotoend ) {
                    var index = 0,
                    // if we are going to the end, we want to run all the tweens
                    // otherwise we skip this part
                        length = gotoend ? animation.tweens.length : 0;
                    if ( stopped ) {
                        return this;
                    }
                    stopped = true;
                    for ( ; index < length ; index++ ) {
                        animation.tweens[ index ].run( 1 );
                    }

                    // resolve when we played the last frame
                    // otherwise, reject
                    if ( gotoend ) {
                        deferred.resolvewith( elem, [ animation, gotoend ] );
                    } else {
                        deferred.rejectwith( elem, [ animation, gotoend ] );
                    }
                    return this;
                }
            }),
            props = animation.props;

        propfilter( props, animation.opts.specialeasing );

        for ( ; index < length ; index++ ) {
            result = animationprefilters[ index ].call( animation, elem, props, animation.opts );
            if ( result ) {
                return result;
            }
        }

        jquery.map( props, createtween, animation );

        if ( jquery.isfunction( animation.opts.start ) ) {
            animation.opts.start.call( elem, animation );
        }

        jquery.fx.timer(
            jquery.extend( tick, {
                elem: elem,
                anim: animation,
                queue: animation.opts.queue
            })
        );

        // attach callbacks from options
        return animation.progress( animation.opts.progress )
            .done( animation.opts.done, animation.opts.complete )
            .fail( animation.opts.fail )
            .always( animation.opts.always );
    }

    function propfilter( props, specialeasing ) {
        var index, name, easing, value, hooks;

        // camelcase, specialeasing and expand csshook pass
        for ( index in props ) {
            name = jquery.camelcase( index );
            easing = specialeasing[ name ];
            value = props[ index ];
            if ( jquery.isarray( value ) ) {
                easing = value[ 1 ];
                value = props[ index ] = value[ 0 ];
            }

            if ( index !== name ) {
                props[ name ] = value;
                delete props[ index ];
            }

            hooks = jquery.csshooks[ name ];
            if ( hooks && "expand" in hooks ) {
                value = hooks.expand( value );
                delete props[ name ];

                // not quite $.extend, this wont overwrite keys already present.
                // also - reusing 'index' from above because we have the correct "name"
                for ( index in value ) {
                    if ( !( index in props ) ) {
                        props[ index ] = value[ index ];
                        specialeasing[ index ] = easing;
                    }
                }
            } else {
                specialeasing[ name ] = easing;
            }
        }
    }

    jquery.animation = jquery.extend( animation, {

        tweener: function( props, callback ) {
            if ( jquery.isfunction( props ) ) {
                callback = props;
                props = [ "*" ];
            } else {
                props = props.split(" ");
            }

            var prop,
                index = 0,
                length = props.length;

            for ( ; index < length ; index++ ) {
                prop = props[ index ];
                tweeners[ prop ] = tweeners[ prop ] || [];
                tweeners[ prop ].unshift( callback );
            }
        },

        prefilter: function( callback, prepend ) {
            if ( prepend ) {
                animationprefilters.unshift( callback );
            } else {
                animationprefilters.push( callback );
            }
        }
    });

    function defaultprefilter( elem, props, opts ) {
        /* jshint validthis: true */
        var prop, value, toggle, tween, hooks, oldfire,
            anim = this,
            orig = {},
            style = elem.style,
            hidden = elem.nodetype && ishidden( elem ),
            datashow = jquery._data( elem, "fxshow" );

        // handle queue: false promises
        if ( !opts.queue ) {
            hooks = jquery._queuehooks( elem, "fx" );
            if ( hooks.unqueued == null ) {
                hooks.unqueued = 0;
                oldfire = hooks.empty.fire;
                hooks.empty.fire = function() {
                    if ( !hooks.unqueued ) {
                        oldfire();
                    }
                };
            }
            hooks.unqueued++;

            anim.always(function() {
                // doing this makes sure that the complete handler will be called
                // before this completes
                anim.always(function() {
                    hooks.unqueued--;
                    if ( !jquery.queue( elem, "fx" ).length ) {
                        hooks.empty.fire();
                    }
                });
            });
        }

        // height/width overflow pass
        if ( elem.nodetype === 1 && ( "height" in props || "width" in props ) ) {
            // make sure that nothing sneaks out
            // record all 3 overflow attributes because ie does not
            // change the overflow attribute when overflowx and
            // overflowy are set to the same value
            opts.overflow = [ style.overflow, style.overflowx, style.overflowy ];

            // set display property to inline-block for height/width
            // animations on inline elements that are having width/height animated
            if ( jquery.css( elem, "display" ) === "inline" &&
                jquery.css( elem, "float" ) === "none" ) {

                // inline-level elements accept inline-block;
                // block-level elements need to be inline with layout
                if ( !jquery.support.inlineblockneedslayout || css_defaultdisplay( elem.nodename ) === "inline" ) {
                    style.display = "inline-block";

                } else {
                    style.zoom = 1;
                }
            }
        }

        if ( opts.overflow ) {
            style.overflow = "hidden";
            if ( !jquery.support.shrinkwrapblocks ) {
                anim.always(function() {
                    style.overflow = opts.overflow[ 0 ];
                    style.overflowx = opts.overflow[ 1 ];
                    style.overflowy = opts.overflow[ 2 ];
                });
            }
        }


        // show/hide pass
        for ( prop in props ) {
            value = props[ prop ];
            if ( rfxtypes.exec( value ) ) {
                delete props[ prop ];
                toggle = toggle || value === "toggle";
                if ( value === ( hidden ? "hide" : "show" ) ) {
                    continue;
                }
                orig[ prop ] = datashow && datashow[ prop ] || jquery.style( elem, prop );
            }
        }

        if ( !jquery.isemptyobject( orig ) ) {
            if ( datashow ) {
                if ( "hidden" in datashow ) {
                    hidden = datashow.hidden;
                }
            } else {
                datashow = jquery._data( elem, "fxshow", {} );
            }

            // store state if its toggle - enables .stop().toggle() to "reverse"
            if ( toggle ) {
                datashow.hidden = !hidden;
            }
            if ( hidden ) {
                jquery( elem ).show();
            } else {
                anim.done(function() {
                    jquery( elem ).hide();
                });
            }
            anim.done(function() {
                var prop;
                jquery._removedata( elem, "fxshow" );
                for ( prop in orig ) {
                    jquery.style( elem, prop, orig[ prop ] );
                }
            });
            for ( prop in orig ) {
                tween = createtween( hidden ? datashow[ prop ] : 0, prop, anim );

                if ( !( prop in datashow ) ) {
                    datashow[ prop ] = tween.start;
                    if ( hidden ) {
                        tween.end = tween.start;
                        tween.start = prop === "width" || prop === "height" ? 1 : 0;
                    }
                }
            }
        }
    }

    function tween( elem, options, prop, end, easing ) {
        return new tween.prototype.init( elem, options, prop, end, easing );
    }
    jquery.tween = tween;

    tween.prototype = {
        constructor: tween,
        init: function( elem, options, prop, end, easing, unit ) {
            this.elem = elem;
            this.prop = prop;
            this.easing = easing || "swing";
            this.options = options;
            this.start = this.now = this.cur();
            this.end = end;
            this.unit = unit || ( jquery.cssnumber[ prop ] ? "" : "px" );
        },
        cur: function() {
            var hooks = tween.prophooks[ this.prop ];

            return hooks && hooks.get ?
                hooks.get( this ) :
                tween.prophooks._default.get( this );
        },
        run: function( percent ) {
            var eased,
                hooks = tween.prophooks[ this.prop ];

            if ( this.options.duration ) {
                this.pos = eased = jquery.easing[ this.easing ](
                    percent, this.options.duration * percent, 0, 1, this.options.duration
                );
            } else {
                this.pos = eased = percent;
            }
            this.now = ( this.end - this.start ) * eased + this.start;

            if ( this.options.step ) {
                this.options.step.call( this.elem, this.now, this );
            }

            if ( hooks && hooks.set ) {
                hooks.set( this );
            } else {
                tween.prophooks._default.set( this );
            }
            return this;
        }
    };

    tween.prototype.init.prototype = tween.prototype;

    tween.prophooks = {
        _default: {
            get: function( tween ) {
                var result;

                if ( tween.elem[ tween.prop ] != null &&
                    (!tween.elem.style || tween.elem.style[ tween.prop ] == null) ) {
                    return tween.elem[ tween.prop ];
                }

                // passing an empty string as a 3rd parameter to .css will automatically
                // attempt a parsefloat and fallback to a string if the parse fails
                // so, simple values such as "10px" are parsed to float.
                // complex values such as "rotate(1rad)" are returned as is.
                result = jquery.css( tween.elem, tween.prop, "" );
                // empty strings, null, undefined and "auto" are converted to 0.
                return !result || result === "auto" ? 0 : result;
            },
            set: function( tween ) {
                // use step hook for back compat - use csshook if its there - use .style if its
                // available and use plain properties where available
                if ( jquery.fx.step[ tween.prop ] ) {
                    jquery.fx.step[ tween.prop ]( tween );
                } else if ( tween.elem.style && ( tween.elem.style[ jquery.cssprops[ tween.prop ] ] != null || jquery.csshooks[ tween.prop ] ) ) {
                    jquery.style( tween.elem, tween.prop, tween.now + tween.unit );
                } else {
                    tween.elem[ tween.prop ] = tween.now;
                }
            }
        }
    };

// support: ie <=9
// panic based approach to setting things on disconnected nodes

    tween.prophooks.scrolltop = tween.prophooks.scrollleft = {
        set: function( tween ) {
            if ( tween.elem.nodetype && tween.elem.parentnode ) {
                tween.elem[ tween.prop ] = tween.now;
            }
        }
    };

    jquery.each([ "toggle", "show", "hide" ], function( i, name ) {
        var cssfn = jquery.fn[ name ];
        jquery.fn[ name ] = function( speed, easing, callback ) {
            return speed == null || typeof speed === "boolean" ?
                cssfn.apply( this, arguments ) :
                this.animate( genfx( name, true ), speed, easing, callback );
        };
    });

    jquery.fn.extend({
        fadeto: function( speed, to, easing, callback ) {

            // show any hidden elements after setting opacity to 0
            return this.filter( ishidden ).css( "opacity", 0 ).show()

                // animate to the value specified
                .end().animate({ opacity: to }, speed, easing, callback );
        },
        animate: function( prop, speed, easing, callback ) {
            var empty = jquery.isemptyobject( prop ),
                optall = jquery.speed( speed, easing, callback ),
                doanimation = function() {
                    // operate on a copy of prop so per-property easing won't be lost
                    var anim = animation( this, jquery.extend( {}, prop ), optall );

                    // empty animations, or finishing resolves immediately
                    if ( empty || jquery._data( this, "finish" ) ) {
                        anim.stop( true );
                    }
                };
            doanimation.finish = doanimation;

            return empty || optall.queue === false ?
                this.each( doanimation ) :
                this.queue( optall.queue, doanimation );
        },
        stop: function( type, clearqueue, gotoend ) {
            var stopqueue = function( hooks ) {
                var stop = hooks.stop;
                delete hooks.stop;
                stop( gotoend );
            };

            if ( typeof type !== "string" ) {
                gotoend = clearqueue;
                clearqueue = type;
                type = undefined;
            }
            if ( clearqueue && type !== false ) {
                this.queue( type || "fx", [] );
            }

            return this.each(function() {
                var dequeue = true,
                    index = type != null && type + "queuehooks",
                    timers = jquery.timers,
                    data = jquery._data( this );

                if ( index ) {
                    if ( data[ index ] && data[ index ].stop ) {
                        stopqueue( data[ index ] );
                    }
                } else {
                    for ( index in data ) {
                        if ( data[ index ] && data[ index ].stop && rrun.test( index ) ) {
                            stopqueue( data[ index ] );
                        }
                    }
                }

                for ( index = timers.length; index--; ) {
                    if ( timers[ index ].elem === this && (type == null || timers[ index ].queue === type) ) {
                        timers[ index ].anim.stop( gotoend );
                        dequeue = false;
                        timers.splice( index, 1 );
                    }
                }

                // start the next in the queue if the last step wasn't forced
                // timers currently will call their complete callbacks, which will dequeue
                // but only if they were gotoend
                if ( dequeue || !gotoend ) {
                    jquery.dequeue( this, type );
                }
            });
        },
        finish: function( type ) {
            if ( type !== false ) {
                type = type || "fx";
            }
            return this.each(function() {
                var index,
                    data = jquery._data( this ),
                    queue = data[ type + "queue" ],
                    hooks = data[ type + "queuehooks" ],
                    timers = jquery.timers,
                    length = queue ? queue.length : 0;

                // enable finishing flag on private data
                data.finish = true;

                // empty the queue first
                jquery.queue( this, type, [] );

                if ( hooks && hooks.stop ) {
                    hooks.stop.call( this, true );
                }

                // look for any active animations, and finish them
                for ( index = timers.length; index--; ) {
                    if ( timers[ index ].elem === this && timers[ index ].queue === type ) {
                        timers[ index ].anim.stop( true );
                        timers.splice( index, 1 );
                    }
                }

                // look for any animations in the old queue and finish them
                for ( index = 0; index < length; index++ ) {
                    if ( queue[ index ] && queue[ index ].finish ) {
                        queue[ index ].finish.call( this );
                    }
                }

                // turn off finishing flag
                delete data.finish;
            });
        }
    });

// generate parameters to create a standard animation
    function genfx( type, includewidth ) {
        var which,
            attrs = { height: type },
            i = 0;

        // if we include width, step value is 1 to do all cssexpand values,
        // if we don't include width, step value is 2 to skip over left and right
        includewidth = includewidth? 1 : 0;
        for( ; i < 4 ; i += 2 - includewidth ) {
            which = cssexpand[ i ];
            attrs[ "margin" + which ] = attrs[ "padding" + which ] = type;
        }

        if ( includewidth ) {
            attrs.opacity = attrs.width = type;
        }

        return attrs;
    }

// generate shortcuts for custom animations
    jquery.each({
        slidedown: genfx("show"),
        slideup: genfx("hide"),
        slidetoggle: genfx("toggle"),
        fadein: { opacity: "show" },
        fadeout: { opacity: "hide" },
        fadetoggle: { opacity: "toggle" }
    }, function( name, props ) {
        jquery.fn[ name ] = function( speed, easing, callback ) {
            return this.animate( props, speed, easing, callback );
        };
    });

    jquery.speed = function( speed, easing, fn ) {
        var opt = speed && typeof speed === "object" ? jquery.extend( {}, speed ) : {
            complete: fn || !fn && easing ||
                jquery.isfunction( speed ) && speed,
            duration: speed,
            easing: fn && easing || easing && !jquery.isfunction( easing ) && easing
        };

        opt.duration = jquery.fx.off ? 0 : typeof opt.duration === "number" ? opt.duration :
                opt.duration in jquery.fx.speeds ? jquery.fx.speeds[ opt.duration ] : jquery.fx.speeds._default;

        // normalize opt.queue - true/undefined/null -> "fx"
        if ( opt.queue == null || opt.queue === true ) {
            opt.queue = "fx";
        }

        // queueing
        opt.old = opt.complete;

        opt.complete = function() {
            if ( jquery.isfunction( opt.old ) ) {
                opt.old.call( this );
            }

            if ( opt.queue ) {
                jquery.dequeue( this, opt.queue );
            }
        };

        return opt;
    };

    jquery.easing = {
        linear: function( p ) {
            return p;
        },
        swing: function( p ) {
            return 0.5 - math.cos( p*math.pi ) / 2;
        }
    };

    jquery.timers = [];
    jquery.fx = tween.prototype.init;
    jquery.fx.tick = function() {
        var timer,
            timers = jquery.timers,
            i = 0;

        fxnow = jquery.now();

        for ( ; i < timers.length; i++ ) {
            timer = timers[ i ];
            // checks the timer has not already been removed
            if ( !timer() && timers[ i ] === timer ) {
                timers.splice( i--, 1 );
            }
        }

        if ( !timers.length ) {
            jquery.fx.stop();
        }
        fxnow = undefined;
    };

    jquery.fx.timer = function( timer ) {
        if ( timer() && jquery.timers.push( timer ) ) {
            jquery.fx.start();
        }
    };

    jquery.fx.interval = 13;

    jquery.fx.start = function() {
        if ( !timerid ) {
            timerid = setinterval( jquery.fx.tick, jquery.fx.interval );
        }
    };

    jquery.fx.stop = function() {
        clearinterval( timerid );
        timerid = null;
    };

    jquery.fx.speeds = {
        slow: 600,
        fast: 200,
        // default speed
        _default: 400
    };

// back compat <1.8 extension point
    jquery.fx.step = {};

    if ( jquery.expr && jquery.expr.filters ) {
        jquery.expr.filters.animated = function( elem ) {
            return jquery.grep(jquery.timers, function( fn ) {
                return elem === fn.elem;
            }).length;
        };
    }
    jquery.fn.offset = function( options ) {
        if ( arguments.length ) {
            return options === undefined ?
                this :
                this.each(function( i ) {
                    jquery.offset.setoffset( this, options, i );
                });
        }

        var docelem, win,
            box = { top: 0, left: 0 },
            elem = this[ 0 ],
            doc = elem && elem.ownerdocument;

        if ( !doc ) {
            return;
        }

        docelem = doc.documentelement;

        // make sure it's not a disconnected dom node
        if ( !jquery.contains( docelem, elem ) ) {
            return box;
        }

        // if we don't have gbcr, just use 0,0 rather than error
        // blackberry 5, ios 3 (original iphone)
        if ( typeof elem.getboundingclientrect !== core_strundefined ) {
            box = elem.getboundingclientrect();
        }
        win = getwindow( doc );
        return {
            top: box.top  + ( win.pageyoffset || docelem.scrolltop )  - ( docelem.clienttop  || 0 ),
            left: box.left + ( win.pagexoffset || docelem.scrollleft ) - ( docelem.clientleft || 0 )
        };
    };

    jquery.offset = {

        setoffset: function( elem, options, i ) {
            var position = jquery.css( elem, "position" );

            // set position first, in-case top/left are set even on static elem
            if ( position === "static" ) {
                elem.style.position = "relative";
            }

            var curelem = jquery( elem ),
                curoffset = curelem.offset(),
                curcsstop = jquery.css( elem, "top" ),
                curcssleft = jquery.css( elem, "left" ),
                calculateposition = ( position === "absolute" || position === "fixed" ) && jquery.inarray("auto", [curcsstop, curcssleft]) > -1,
                props = {}, curposition = {}, curtop, curleft;

            // need to be able to calculate position if either top or left is auto and position is either absolute or fixed
            if ( calculateposition ) {
                curposition = curelem.position();
                curtop = curposition.top;
                curleft = curposition.left;
            } else {
                curtop = parsefloat( curcsstop ) || 0;
                curleft = parsefloat( curcssleft ) || 0;
            }

            if ( jquery.isfunction( options ) ) {
                options = options.call( elem, i, curoffset );
            }

            if ( options.top != null ) {
                props.top = ( options.top - curoffset.top ) + curtop;
            }
            if ( options.left != null ) {
                props.left = ( options.left - curoffset.left ) + curleft;
            }

            if ( "using" in options ) {
                options.using.call( elem, props );
            } else {
                curelem.css( props );
            }
        }
    };


    jquery.fn.extend({

        position: function() {
            if ( !this[ 0 ] ) {
                return;
            }

            var offsetparent, offset,
                parentoffset = { top: 0, left: 0 },
                elem = this[ 0 ];

            // fixed elements are offset from window (parentoffset = {top:0, left: 0}, because it is it's only offset parent
            if ( jquery.css( elem, "position" ) === "fixed" ) {
                // we assume that getboundingclientrect is available when computed position is fixed
                offset = elem.getboundingclientrect();
            } else {
                // get *real* offsetparent
                offsetparent = this.offsetparent();

                // get correct offsets
                offset = this.offset();
                if ( !jquery.nodename( offsetparent[ 0 ], "html" ) ) {
                    parentoffset = offsetparent.offset();
                }

                // add offsetparent borders
                parentoffset.top  += jquery.css( offsetparent[ 0 ], "bordertopwidth", true );
                parentoffset.left += jquery.css( offsetparent[ 0 ], "borderleftwidth", true );
            }

            // subtract parent offsets and element margins
            // note: when an element has margin: auto the offsetleft and marginleft
            // are the same in safari causing offset.left to incorrectly be 0
            return {
                top:  offset.top  - parentoffset.top - jquery.css( elem, "margintop", true ),
                left: offset.left - parentoffset.left - jquery.css( elem, "marginleft", true)
            };
        },

        offsetparent: function() {
            return this.map(function() {
                var offsetparent = this.offsetparent || docelem;
                while ( offsetparent && ( !jquery.nodename( offsetparent, "html" ) && jquery.css( offsetparent, "position") === "static" ) ) {
                    offsetparent = offsetparent.offsetparent;
                }
                return offsetparent || docelem;
            });
        }
    });


// create scrollleft and scrolltop methods
    jquery.each( {scrollleft: "pagexoffset", scrolltop: "pageyoffset"}, function( method, prop ) {
        var top = /y/.test( prop );

        jquery.fn[ method ] = function( val ) {
            return jquery.access( this, function( elem, method, val ) {
                var win = getwindow( elem );

                if ( val === undefined ) {
                    return win ? (prop in win) ? win[ prop ] :
                        win.document.documentelement[ method ] :
                        elem[ method ];
                }

                if ( win ) {
                    win.scrollto(
                        !top ? val : jquery( win ).scrollleft(),
                        top ? val : jquery( win ).scrolltop()
                    );

                } else {
                    elem[ method ] = val;
                }
            }, method, val, arguments.length, null );
        };
    });

    function getwindow( elem ) {
        return jquery.iswindow( elem ) ?
            elem :
                elem.nodetype === 9 ?
            elem.defaultview || elem.parentwindow :
            false;
    }
// create innerheight, innerwidth, height, width, outerheight and outerwidth methods
    jquery.each( { height: "height", width: "width" }, function( name, type ) {
        jquery.each( { padding: "inner" + name, content: type, "": "outer" + name }, function( defaultextra, funcname ) {
            // margin is only for outerheight, outerwidth
            jquery.fn[ funcname ] = function( margin, value ) {
                var chainable = arguments.length && ( defaultextra || typeof margin !== "boolean" ),
                    extra = defaultextra || ( margin === true || value === true ? "margin" : "border" );

                return jquery.access( this, function( elem, type, value ) {
                    var doc;

                    if ( jquery.iswindow( elem ) ) {
                        // as of 5/8/2012 this will yield incorrect results for mobile safari, but there
                        // isn't a whole lot we can do. see pull request at this url for discussion:
                        // https://github.com/jquery/jquery/pull/764
                        return elem.document.documentelement[ "client" + name ];
                    }

                    // get document width or height
                    if ( elem.nodetype === 9 ) {
                        doc = elem.documentelement;

                        // either scroll[width/height] or offset[width/height] or client[width/height], whichever is greatest
                        // unfortunately, this causes bug #3838 in ie6/8 only, but there is currently no good, small way to fix it.
                        return math.max(
                            elem.body[ "scroll" + name ], doc[ "scroll" + name ],
                            elem.body[ "offset" + name ], doc[ "offset" + name ],
                            doc[ "client" + name ]
                        );
                    }

                    return value === undefined ?
                        // get width or height on the element, requesting but not forcing parsefloat
                        jquery.css( elem, type, extra ) :

                        // set width or height on the element
                        jquery.style( elem, type, value, extra );
                }, type, chainable ? margin : undefined, chainable, null );
            };
        });
    });
// limit scope pollution from any deprecated api
// (function() {

// the number of elements contained in the matched element set
    jquery.fn.size = function() {
        return this.length;
    };

    jquery.fn.andself = jquery.fn.addback;

// })();
    if ( typeof module === "object" && module && typeof module.exports === "object" ) {
        // expose jquery as module.exports in loaders that implement the node
        // module pattern (including browserify). do not create the global, since
        // the user will be storing it themselves locally, and globals are frowned
        // upon in the node module world.
        module.exports = jquery;
    } else {
        // otherwise expose jquery to the global object as usual
        window.jquery = window.$ = jquery;

        // register as a named amd module, since jquery can be concatenated with other
        // files that may use define, but not via a proper concatenation script that
        // understands anonymous amd modules. a named amd is safest and most robust
        // way to register. lowercase jquery is used because amd module names are
        // derived from file names, and jquery is normally delivered in a lowercase
        // file name. do this after creating the global so that if an amd module wants
        // to call noconflict to hide this version of jquery, it will work.
        if ( typeof define === "function" && define.amd ) {
            define( "jquery", [], function () { return jquery; } );
        }
    }

})( window );