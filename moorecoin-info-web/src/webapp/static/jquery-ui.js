/*! jquery ui - v1.11.2 - 2014-10-16
 * http://jqueryui.com
 * includes: core.js, widget.js, mouse.js, position.js, accordion.js, autocomplete.js, button.js, datepicker.js, dialog.js, draggable.js, droppable.js, effect.js, effect-blind.js, effect-bounce.js, effect-clip.js, effect-drop.js, effect-explode.js, effect-fade.js, effect-fold.js, effect-highlight.js, effect-puff.js, effect-pulsate.js, effect-scale.js, effect-shake.js, effect-size.js, effect-slide.js, effect-transfer.js, menu.js, progressbar.js, resizable.js, selectable.js, selectmenu.js, slider.js, sortable.js, spinner.js, tabs.js, tooltip.js
 * copyright 2014 jquery foundation and other contributors; licensed mit */

(function( factory ) {
    if ( typeof define === "function" && define.amd ) {

        // amd. register as an anonymous module.
        define([ "jquery" ], factory );
    } else {

        // browser globals
        factory( jquery );
    }
}(function( $ ) {
    /*!
     * jquery ui core 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/category/ui-core/
     */


// $.ui might exist from components with no dependencies, e.g., $.ui.position
    $.ui = $.ui || {};

    $.extend( $.ui, {
        version: "1.11.2",

        keycode: {
            backspace: 8,
            comma: 188,
            delete: 46,
            down: 40,
            end: 35,
            enter: 13,
            escape: 27,
            home: 36,
            left: 37,
            page_down: 34,
            page_up: 33,
            period: 190,
            right: 39,
            space: 32,
            tab: 9,
            up: 38
        }
    });

// plugins
    $.fn.extend({
        scrollparent: function( includehidden ) {
            var position = this.css( "position" ),
                excludestaticparent = position === "absolute",
                overflowregex = includehidden ? /(auto|scroll|hidden)/ : /(auto|scroll)/,
                scrollparent = this.parents().filter( function() {
                    var parent = $( this );
                    if ( excludestaticparent && parent.css( "position" ) === "static" ) {
                        return false;
                    }
                    return overflowregex.test( parent.css( "overflow" ) + parent.css( "overflow-y" ) + parent.css( "overflow-x" ) );
                }).eq( 0 );

            return position === "fixed" || !scrollparent.length ? $( this[ 0 ].ownerdocument || document ) : scrollparent;
        },

        uniqueid: (function() {
            var uuid = 0;

            return function() {
                return this.each(function() {
                    if ( !this.id ) {
                        this.id = "ui-id-" + ( ++uuid );
                    }
                });
            };
        })(),

        removeuniqueid: function() {
            return this.each(function() {
                if ( /^ui-id-\d+$/.test( this.id ) ) {
                    $( this ).removeattr( "id" );
                }
            });
        }
    });

// selectors
    function focusable( element, istabindexnotnan ) {
        var map, mapname, img,
            nodename = element.nodename.tolowercase();
        if ( "area" === nodename ) {
            map = element.parentnode;
            mapname = map.name;
            if ( !element.href || !mapname || map.nodename.tolowercase() !== "map" ) {
                return false;
            }
            img = $( "img[usemap='#" + mapname + "']" )[ 0 ];
            return !!img && visible( img );
        }
        return ( /input|select|textarea|button|object/.test( nodename ) ?
            !element.disabled :
                "a" === nodename ?
            element.href || istabindexnotnan :
            istabindexnotnan) &&
            // the element and all of its ancestors must be visible
            visible( element );
    }

    function visible( element ) {
        return $.expr.filters.visible( element ) &&
            !$( element ).parents().addback().filter(function() {
                return $.css( this, "visibility" ) === "hidden";
            }).length;
    }

    $.extend( $.expr[ ":" ], {
        data: $.expr.createpseudo ?
            $.expr.createpseudo(function( dataname ) {
                return function( elem ) {
                    return !!$.data( elem, dataname );
                };
            }) :
            // support: jquery <1.8
            function( elem, i, match ) {
                return !!$.data( elem, match[ 3 ] );
            },

        focusable: function( element ) {
            return focusable( element, !isnan( $.attr( element, "tabindex" ) ) );
        },

        tabbable: function( element ) {
            var tabindex = $.attr( element, "tabindex" ),
                istabindexnan = isnan( tabindex );
            return ( istabindexnan || tabindex >= 0 ) && focusable( element, !istabindexnan );
        }
    });

// support: jquery <1.8
    if ( !$( "<a>" ).outerwidth( 1 ).jquery ) {
        $.each( [ "width", "height" ], function( i, name ) {
            var side = name === "width" ? [ "left", "right" ] : [ "top", "bottom" ],
                type = name.tolowercase(),
                orig = {
                    innerwidth: $.fn.innerwidth,
                    innerheight: $.fn.innerheight,
                    outerwidth: $.fn.outerwidth,
                    outerheight: $.fn.outerheight
                };

            function reduce( elem, size, border, margin ) {
                $.each( side, function() {
                    size -= parsefloat( $.css( elem, "padding" + this ) ) || 0;
                    if ( border ) {
                        size -= parsefloat( $.css( elem, "border" + this + "width" ) ) || 0;
                    }
                    if ( margin ) {
                        size -= parsefloat( $.css( elem, "margin" + this ) ) || 0;
                    }
                });
                return size;
            }

            $.fn[ "inner" + name ] = function( size ) {
                if ( size === undefined ) {
                    return orig[ "inner" + name ].call( this );
                }

                return this.each(function() {
                    $( this ).css( type, reduce( this, size ) + "px" );
                });
            };

            $.fn[ "outer" + name] = function( size, margin ) {
                if ( typeof size !== "number" ) {
                    return orig[ "outer" + name ].call( this, size );
                }

                return this.each(function() {
                    $( this).css( type, reduce( this, size, true, margin ) + "px" );
                });
            };
        });
    }

// support: jquery <1.8
    if ( !$.fn.addback ) {
        $.fn.addback = function( selector ) {
            return this.add( selector == null ?
                    this.prevobject : this.prevobject.filter( selector )
            );
        };
    }

// support: jquery 1.6.1, 1.6.2 (http://bugs.jquery.com/ticket/9413)
    if ( $( "<a>" ).data( "a-b", "a" ).removedata( "a-b" ).data( "a-b" ) ) {
        $.fn.removedata = (function( removedata ) {
            return function( key ) {
                if ( arguments.length ) {
                    return removedata.call( this, $.camelcase( key ) );
                } else {
                    return removedata.call( this );
                }
            };
        })( $.fn.removedata );
    }

// deprecated
    $.ui.ie = !!/msie [\w.]+/.exec( navigator.useragent.tolowercase() );

    $.fn.extend({
        focus: (function( orig ) {
            return function( delay, fn ) {
                return typeof delay === "number" ?
                    this.each(function() {
                        var elem = this;
                        settimeout(function() {
                            $( elem ).focus();
                            if ( fn ) {
                                fn.call( elem );
                            }
                        }, delay );
                    }) :
                    orig.apply( this, arguments );
            };
        })( $.fn.focus ),

        disableselection: (function() {
            var eventtype = "onselectstart" in document.createelement( "div" ) ?
                "selectstart" :
                "mousedown";

            return function() {
                return this.bind( eventtype + ".ui-disableselection", function( event ) {
                    event.preventdefault();
                });
            };
        })(),

        enableselection: function() {
            return this.unbind( ".ui-disableselection" );
        },

        zindex: function( zindex ) {
            if ( zindex !== undefined ) {
                return this.css( "zindex", zindex );
            }

            if ( this.length ) {
                var elem = $( this[ 0 ] ), position, value;
                while ( elem.length && elem[ 0 ] !== document ) {
                    // ignore z-index if position is set to a value where z-index is ignored by the browser
                    // this makes behavior of this function consistent across browsers
                    // webkit always returns auto if the element is positioned
                    position = elem.css( "position" );
                    if ( position === "absolute" || position === "relative" || position === "fixed" ) {
                        // ie returns 0 when zindex is not specified
                        // other browsers return a string
                        // we ignore the case of nested elements with an explicit value of 0
                        // <div style="z-index: -10;"><div style="z-index: 0;"></div></div>
                        value = parseint( elem.css( "zindex" ), 10 );
                        if ( !isnan( value ) && value !== 0 ) {
                            return value;
                        }
                    }
                    elem = elem.parent();
                }
            }

            return 0;
        }
    });

// $.ui.plugin is deprecated. use $.widget() extensions instead.
    $.ui.plugin = {
        add: function( module, option, set ) {
            var i,
                proto = $.ui[ module ].prototype;
            for ( i in set ) {
                proto.plugins[ i ] = proto.plugins[ i ] || [];
                proto.plugins[ i ].push( [ option, set[ i ] ] );
            }
        },
        call: function( instance, name, args, allowdisconnected ) {
            var i,
                set = instance.plugins[ name ];

            if ( !set ) {
                return;
            }

            if ( !allowdisconnected && ( !instance.element[ 0 ].parentnode || instance.element[ 0 ].parentnode.nodetype === 11 ) ) {
                return;
            }

            for ( i = 0; i < set.length; i++ ) {
                if ( instance.options[ set[ i ][ 0 ] ] ) {
                    set[ i ][ 1 ].apply( instance.element, args );
                }
            }
        }
    };


    /*!
     * jquery ui widget 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/jquery.widget/
     */


    var widget_uuid = 0,
        widget_slice = array.prototype.slice;

    $.cleandata = (function( orig ) {
        return function( elems ) {
            var events, elem, i;
            for ( i = 0; (elem = elems[i]) != null; i++ ) {
                try {

                    // only trigger remove when necessary to save time
                    events = $._data( elem, "events" );
                    if ( events && events.remove ) {
                        $( elem ).triggerhandler( "remove" );
                    }

                    // http://bugs.jquery.com/ticket/8235
                } catch ( e ) {}
            }
            orig( elems );
        };
    })( $.cleandata );

    $.widget = function( name, base, prototype ) {
        var fullname, existingconstructor, constructor, baseprototype,
        // proxiedprototype allows the provided prototype to remain unmodified
        // so that it can be used as a mixin for multiple widgets (#8876)
            proxiedprototype = {},
            namespace = name.split( "." )[ 0 ];

        name = name.split( "." )[ 1 ];
        fullname = namespace + "-" + name;

        if ( !prototype ) {
            prototype = base;
            base = $.widget;
        }

        // create selector for plugin
        $.expr[ ":" ][ fullname.tolowercase() ] = function( elem ) {
            return !!$.data( elem, fullname );
        };

        $[ namespace ] = $[ namespace ] || {};
        existingconstructor = $[ namespace ][ name ];
        constructor = $[ namespace ][ name ] = function( options, element ) {
            // allow instantiation without "new" keyword
            if ( !this._createwidget ) {
                return new constructor( options, element );
            }

            // allow instantiation without initializing for simple inheritance
            // must use "new" keyword (the code above always passes args)
            if ( arguments.length ) {
                this._createwidget( options, element );
            }
        };
        // extend with the existing constructor to carry over any static properties
        $.extend( constructor, existingconstructor, {
            version: prototype.version,
            // copy the object used to create the prototype in case we need to
            // redefine the widget later
            _proto: $.extend( {}, prototype ),
            // track widgets that inherit from this widget in case this widget is
            // redefined after a widget inherits from it
            _childconstructors: []
        });

        baseprototype = new base();
        // we need to make the options hash a property directly on the new instance
        // otherwise we'll modify the options hash on the prototype that we're
        // inheriting from
        baseprototype.options = $.widget.extend( {}, baseprototype.options );
        $.each( prototype, function( prop, value ) {
            if ( !$.isfunction( value ) ) {
                proxiedprototype[ prop ] = value;
                return;
            }
            proxiedprototype[ prop ] = (function() {
                var _super = function() {
                        return base.prototype[ prop ].apply( this, arguments );
                    },
                    _superapply = function( args ) {
                        return base.prototype[ prop ].apply( this, args );
                    };
                return function() {
                    var __super = this._super,
                        __superapply = this._superapply,
                        returnvalue;

                    this._super = _super;
                    this._superapply = _superapply;

                    returnvalue = value.apply( this, arguments );

                    this._super = __super;
                    this._superapply = __superapply;

                    return returnvalue;
                };
            })();
        });
        constructor.prototype = $.widget.extend( baseprototype, {
            // todo: remove support for widgeteventprefix
            // always use the name + a colon as the prefix, e.g., draggable:start
            // don't prefix for widgets that aren't dom-based
            widgeteventprefix: existingconstructor ? (baseprototype.widgeteventprefix || name) : name
        }, proxiedprototype, {
            constructor: constructor,
            namespace: namespace,
            widgetname: name,
            widgetfullname: fullname
        });

        // if this widget is being redefined then we need to find all widgets that
        // are inheriting from it and redefine all of them so that they inherit from
        // the new version of this widget. we're essentially trying to replace one
        // level in the prototype chain.
        if ( existingconstructor ) {
            $.each( existingconstructor._childconstructors, function( i, child ) {
                var childprototype = child.prototype;

                // redefine the child widget using the same prototype that was
                // originally used, but inherit from the new version of the base
                $.widget( childprototype.namespace + "." + childprototype.widgetname, constructor, child._proto );
            });
            // remove the list of existing child constructors from the old constructor
            // so the old child constructors can be garbage collected
            delete existingconstructor._childconstructors;
        } else {
            base._childconstructors.push( constructor );
        }

        $.widget.bridge( name, constructor );

        return constructor;
    };

    $.widget.extend = function( target ) {
        var input = widget_slice.call( arguments, 1 ),
            inputindex = 0,
            inputlength = input.length,
            key,
            value;
        for ( ; inputindex < inputlength; inputindex++ ) {
            for ( key in input[ inputindex ] ) {
                value = input[ inputindex ][ key ];
                if ( input[ inputindex ].hasownproperty( key ) && value !== undefined ) {
                    // clone objects
                    if ( $.isplainobject( value ) ) {
                        target[ key ] = $.isplainobject( target[ key ] ) ?
                            $.widget.extend( {}, target[ key ], value ) :
                            // don't extend strings, arrays, etc. with objects
                            $.widget.extend( {}, value );
                        // copy everything else by reference
                    } else {
                        target[ key ] = value;
                    }
                }
            }
        }
        return target;
    };

    $.widget.bridge = function( name, object ) {
        var fullname = object.prototype.widgetfullname || name;
        $.fn[ name ] = function( options ) {
            var ismethodcall = typeof options === "string",
                args = widget_slice.call( arguments, 1 ),
                returnvalue = this;

            // allow multiple hashes to be passed on init
            options = !ismethodcall && args.length ?
                $.widget.extend.apply( null, [ options ].concat(args) ) :
                options;

            if ( ismethodcall ) {
                this.each(function() {
                    var methodvalue,
                        instance = $.data( this, fullname );
                    if ( options === "instance" ) {
                        returnvalue = instance;
                        return false;
                    }
                    if ( !instance ) {
                        return $.error( "cannot call methods on " + name + " prior to initialization; " +
                            "attempted to call method '" + options + "'" );
                    }
                    if ( !$.isfunction( instance[options] ) || options.charat( 0 ) === "_" ) {
                        return $.error( "no such method '" + options + "' for " + name + " widget instance" );
                    }
                    methodvalue = instance[ options ].apply( instance, args );
                    if ( methodvalue !== instance && methodvalue !== undefined ) {
                        returnvalue = methodvalue && methodvalue.jquery ?
                            returnvalue.pushstack( methodvalue.get() ) :
                            methodvalue;
                        return false;
                    }
                });
            } else {
                this.each(function() {
                    var instance = $.data( this, fullname );
                    if ( instance ) {
                        instance.option( options || {} );
                        if ( instance._init ) {
                            instance._init();
                        }
                    } else {
                        $.data( this, fullname, new object( options, this ) );
                    }
                });
            }

            return returnvalue;
        };
    };

    $.widget = function( /* options, element */ ) {};
    $.widget._childconstructors = [];

    $.widget.prototype = {
        widgetname: "widget",
        widgeteventprefix: "",
        defaultelement: "<div>",
        options: {
            disabled: false,

            // callbacks
            create: null
        },
        _createwidget: function( options, element ) {
            element = $( element || this.defaultelement || this )[ 0 ];
            this.element = $( element );
            this.uuid = widget_uuid++;
            this.eventnamespace = "." + this.widgetname + this.uuid;

            this.bindings = $();
            this.hoverable = $();
            this.focusable = $();

            if ( element !== this ) {
                $.data( element, this.widgetfullname, this );
                this._on( true, this.element, {
                    remove: function( event ) {
                        if ( event.target === element ) {
                            this.destroy();
                        }
                    }
                });
                this.document = $( element.style ?
                    // element within the document
                    element.ownerdocument :
                    // element is window or document
                    element.document || element );
                this.window = $( this.document[0].defaultview || this.document[0].parentwindow );
            }

            this.options = $.widget.extend( {},
                this.options,
                this._getcreateoptions(),
                options );

            this._create();
            this._trigger( "create", null, this._getcreateeventdata() );
            this._init();
        },
        _getcreateoptions: $.noop,
        _getcreateeventdata: $.noop,
        _create: $.noop,
        _init: $.noop,

        destroy: function() {
            this._destroy();
            // we can probably remove the unbind calls in 2.0
            // all event bindings should go through this._on()
            this.element
                .unbind( this.eventnamespace )
                .removedata( this.widgetfullname )
                // support: jquery <1.6.3
                // http://bugs.jquery.com/ticket/9413
                .removedata( $.camelcase( this.widgetfullname ) );
            this.widget()
                .unbind( this.eventnamespace )
                .removeattr( "aria-disabled" )
                .removeclass(
                    this.widgetfullname + "-disabled " +
                    "ui-state-disabled" );

            // clean up events and states
            this.bindings.unbind( this.eventnamespace );
            this.hoverable.removeclass( "ui-state-hover" );
            this.focusable.removeclass( "ui-state-focus" );
        },
        _destroy: $.noop,

        widget: function() {
            return this.element;
        },

        option: function( key, value ) {
            var options = key,
                parts,
                curoption,
                i;

            if ( arguments.length === 0 ) {
                // don't return a reference to the internal hash
                return $.widget.extend( {}, this.options );
            }

            if ( typeof key === "string" ) {
                // handle nested keys, e.g., "foo.bar" => { foo: { bar: ___ } }
                options = {};
                parts = key.split( "." );
                key = parts.shift();
                if ( parts.length ) {
                    curoption = options[ key ] = $.widget.extend( {}, this.options[ key ] );
                    for ( i = 0; i < parts.length - 1; i++ ) {
                        curoption[ parts[ i ] ] = curoption[ parts[ i ] ] || {};
                        curoption = curoption[ parts[ i ] ];
                    }
                    key = parts.pop();
                    if ( arguments.length === 1 ) {
                        return curoption[ key ] === undefined ? null : curoption[ key ];
                    }
                    curoption[ key ] = value;
                } else {
                    if ( arguments.length === 1 ) {
                        return this.options[ key ] === undefined ? null : this.options[ key ];
                    }
                    options[ key ] = value;
                }
            }

            this._setoptions( options );

            return this;
        },
        _setoptions: function( options ) {
            var key;

            for ( key in options ) {
                this._setoption( key, options[ key ] );
            }

            return this;
        },
        _setoption: function( key, value ) {
            this.options[ key ] = value;

            if ( key === "disabled" ) {
                this.widget()
                    .toggleclass( this.widgetfullname + "-disabled", !!value );

                // if the widget is becoming disabled, then nothing is interactive
                if ( value ) {
                    this.hoverable.removeclass( "ui-state-hover" );
                    this.focusable.removeclass( "ui-state-focus" );
                }
            }

            return this;
        },

        enable: function() {
            return this._setoptions({ disabled: false });
        },
        disable: function() {
            return this._setoptions({ disabled: true });
        },

        _on: function( suppressdisabledcheck, element, handlers ) {
            var delegateelement,
                instance = this;

            // no suppressdisabledcheck flag, shuffle arguments
            if ( typeof suppressdisabledcheck !== "boolean" ) {
                handlers = element;
                element = suppressdisabledcheck;
                suppressdisabledcheck = false;
            }

            // no element argument, shuffle and use this.element
            if ( !handlers ) {
                handlers = element;
                element = this.element;
                delegateelement = this.widget();
            } else {
                element = delegateelement = $( element );
                this.bindings = this.bindings.add( element );
            }

            $.each( handlers, function( event, handler ) {
                function handlerproxy() {
                    // allow widgets to customize the disabled handling
                    // - disabled as an array instead of boolean
                    // - disabled class as method for disabling individual parts
                    if ( !suppressdisabledcheck &&
                        ( instance.options.disabled === true ||
                            $( this ).hasclass( "ui-state-disabled" ) ) ) {
                        return;
                    }
                    return ( typeof handler === "string" ? instance[ handler ] : handler )
                        .apply( instance, arguments );
                }

                // copy the guid so direct unbinding works
                if ( typeof handler !== "string" ) {
                    handlerproxy.guid = handler.guid =
                        handler.guid || handlerproxy.guid || $.guid++;
                }

                var match = event.match( /^([\w:-]*)\s*(.*)$/ ),
                    eventname = match[1] + instance.eventnamespace,
                    selector = match[2];
                if ( selector ) {
                    delegateelement.delegate( selector, eventname, handlerproxy );
                } else {
                    element.bind( eventname, handlerproxy );
                }
            });
        },

        _off: function( element, eventname ) {
            eventname = (eventname || "").split( " " ).join( this.eventnamespace + " " ) +
                this.eventnamespace;
            element.unbind( eventname ).undelegate( eventname );

            // clear the stack to avoid memory leaks (#10056)
            this.bindings = $( this.bindings.not( element ).get() );
            this.focusable = $( this.focusable.not( element ).get() );
            this.hoverable = $( this.hoverable.not( element ).get() );
        },

        _delay: function( handler, delay ) {
            function handlerproxy() {
                return ( typeof handler === "string" ? instance[ handler ] : handler )
                    .apply( instance, arguments );
            }
            var instance = this;
            return settimeout( handlerproxy, delay || 0 );
        },

        _hoverable: function( element ) {
            this.hoverable = this.hoverable.add( element );
            this._on( element, {
                mouseenter: function( event ) {
                    $( event.currenttarget ).addclass( "ui-state-hover" );
                },
                mouseleave: function( event ) {
                    $( event.currenttarget ).removeclass( "ui-state-hover" );
                }
            });
        },

        _focusable: function( element ) {
            this.focusable = this.focusable.add( element );
            this._on( element, {
                focusin: function( event ) {
                    $( event.currenttarget ).addclass( "ui-state-focus" );
                },
                focusout: function( event ) {
                    $( event.currenttarget ).removeclass( "ui-state-focus" );
                }
            });
        },

        _trigger: function( type, event, data ) {
            var prop, orig,
                callback = this.options[ type ];

            data = data || {};
            event = $.event( event );
            event.type = ( type === this.widgeteventprefix ?
                type :
                this.widgeteventprefix + type ).tolowercase();
            // the original event may come from any element
            // so we need to reset the target on the new event
            event.target = this.element[ 0 ];

            // copy original event properties over to the new event
            orig = event.originalevent;
            if ( orig ) {
                for ( prop in orig ) {
                    if ( !( prop in event ) ) {
                        event[ prop ] = orig[ prop ];
                    }
                }
            }

            this.element.trigger( event, data );
            return !( $.isfunction( callback ) &&
                callback.apply( this.element[0], [ event ].concat( data ) ) === false ||
                event.isdefaultprevented() );
        }
    };

    $.each( { show: "fadein", hide: "fadeout" }, function( method, defaulteffect ) {
        $.widget.prototype[ "_" + method ] = function( element, options, callback ) {
            if ( typeof options === "string" ) {
                options = { effect: options };
            }
            var hasoptions,
                effectname = !options ?
                    method :
                        options === true || typeof options === "number" ?
                    defaulteffect :
                    options.effect || defaulteffect;
            options = options || {};
            if ( typeof options === "number" ) {
                options = { duration: options };
            }
            hasoptions = !$.isemptyobject( options );
            options.complete = callback;
            if ( options.delay ) {
                element.delay( options.delay );
            }
            if ( hasoptions && $.effects && $.effects.effect[ effectname ] ) {
                element[ method ]( options );
            } else if ( effectname !== method && element[ effectname ] ) {
                element[ effectname ]( options.duration, options.easing, callback );
            } else {
                element.queue(function( next ) {
                    $( this )[ method ]();
                    if ( callback ) {
                        callback.call( element[ 0 ] );
                    }
                    next();
                });
            }
        };
    });

    var widget = $.widget;


    /*!
     * jquery ui mouse 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/mouse/
     */


    var mousehandled = false;
    $( document ).mouseup( function() {
        mousehandled = false;
    });

    var mouse = $.widget("ui.mouse", {
        version: "1.11.2",
        options: {
            cancel: "input,textarea,button,select,option",
            distance: 1,
            delay: 0
        },
        _mouseinit: function() {
            var that = this;

            this.element
                .bind("mousedown." + this.widgetname, function(event) {
                    return that._mousedown(event);
                })
                .bind("click." + this.widgetname, function(event) {
                    if (true === $.data(event.target, that.widgetname + ".preventclickevent")) {
                        $.removedata(event.target, that.widgetname + ".preventclickevent");
                        event.stopimmediatepropagation();
                        return false;
                    }
                });

            this.started = false;
        },

        // todo: make sure destroying one instance of mouse doesn't mess with
        // other instances of mouse
        _mousedestroy: function() {
            this.element.unbind("." + this.widgetname);
            if ( this._mousemovedelegate ) {
                this.document
                    .unbind("mousemove." + this.widgetname, this._mousemovedelegate)
                    .unbind("mouseup." + this.widgetname, this._mouseupdelegate);
            }
        },

        _mousedown: function(event) {
            // don't let more than one widget handle mousestart
            if ( mousehandled ) {
                return;
            }

            this._mousemoved = false;

            // we may have missed mouseup (out of window)
            (this._mousestarted && this._mouseup(event));

            this._mousedownevent = event;

            var that = this,
                btnisleft = (event.which === 1),
            // event.target.nodename works around a bug in ie 8 with
            // disabled inputs (#7620)
                eliscancel = (typeof this.options.cancel === "string" && event.target.nodename ? $(event.target).closest(this.options.cancel).length : false);
            if (!btnisleft || eliscancel || !this._mousecapture(event)) {
                return true;
            }

            this.mousedelaymet = !this.options.delay;
            if (!this.mousedelaymet) {
                this._mousedelaytimer = settimeout(function() {
                    that.mousedelaymet = true;
                }, this.options.delay);
            }

            if (this._mousedistancemet(event) && this._mousedelaymet(event)) {
                this._mousestarted = (this._mousestart(event) !== false);
                if (!this._mousestarted) {
                    event.preventdefault();
                    return true;
                }
            }

            // click event may never have fired (gecko & opera)
            if (true === $.data(event.target, this.widgetname + ".preventclickevent")) {
                $.removedata(event.target, this.widgetname + ".preventclickevent");
            }

            // these delegates are required to keep context
            this._mousemovedelegate = function(event) {
                return that._mousemove(event);
            };
            this._mouseupdelegate = function(event) {
                return that._mouseup(event);
            };

            this.document
                .bind( "mousemove." + this.widgetname, this._mousemovedelegate )
                .bind( "mouseup." + this.widgetname, this._mouseupdelegate );

            event.preventdefault();

            mousehandled = true;
            return true;
        },

        _mousemove: function(event) {
            // only check for mouseups outside the document if you've moved inside the document
            // at least once. this prevents the firing of mouseup in the case of ie<9, which will
            // fire a mousemove event if content is placed under the cursor. see #7778
            // support: ie <9
            if ( this._mousemoved ) {
                // ie mouseup check - mouseup happened when mouse was out of window
                if ($.ui.ie && ( !document.documentmode || document.documentmode < 9 ) && !event.button) {
                    return this._mouseup(event);

                    // iframe mouseup check - mouseup occurred in another document
                } else if ( !event.which ) {
                    return this._mouseup( event );
                }
            }

            if ( event.which || event.button ) {
                this._mousemoved = true;
            }

            if (this._mousestarted) {
                this._mousedrag(event);
                return event.preventdefault();
            }

            if (this._mousedistancemet(event) && this._mousedelaymet(event)) {
                this._mousestarted =
                    (this._mousestart(this._mousedownevent, event) !== false);
                (this._mousestarted ? this._mousedrag(event) : this._mouseup(event));
            }

            return !this._mousestarted;
        },

        _mouseup: function(event) {
            this.document
                .unbind( "mousemove." + this.widgetname, this._mousemovedelegate )
                .unbind( "mouseup." + this.widgetname, this._mouseupdelegate );

            if (this._mousestarted) {
                this._mousestarted = false;

                if (event.target === this._mousedownevent.target) {
                    $.data(event.target, this.widgetname + ".preventclickevent", true);
                }

                this._mousestop(event);
            }

            mousehandled = false;
            return false;
        },

        _mousedistancemet: function(event) {
            return (math.max(
                math.abs(this._mousedownevent.pagex - event.pagex),
                math.abs(this._mousedownevent.pagey - event.pagey)
            ) >= this.options.distance
                );
        },

        _mousedelaymet: function(/* event */) {
            return this.mousedelaymet;
        },

        // these are placeholder methods, to be overriden by extending plugin
        _mousestart: function(/* event */) {},
        _mousedrag: function(/* event */) {},
        _mousestop: function(/* event */) {},
        _mousecapture: function(/* event */) { return true; }
    });


    /*!
     * jquery ui position 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/position/
     */

    (function() {

        $.ui = $.ui || {};

        var cachedscrollbarwidth, supportsoffsetfractions,
            max = math.max,
            abs = math.abs,
            round = math.round,
            rhorizontal = /left|center|right/,
            rvertical = /top|center|bottom/,
            roffset = /[\+\-]\d+(\.[\d]+)?%?/,
            rposition = /^\w+/,
            rpercent = /%$/,
            _position = $.fn.position;

        function getoffsets( offsets, width, height ) {
            return [
                    parsefloat( offsets[ 0 ] ) * ( rpercent.test( offsets[ 0 ] ) ? width / 100 : 1 ),
                    parsefloat( offsets[ 1 ] ) * ( rpercent.test( offsets[ 1 ] ) ? height / 100 : 1 )
            ];
        }

        function parsecss( element, property ) {
            return parseint( $.css( element, property ), 10 ) || 0;
        }

        function getdimensions( elem ) {
            var raw = elem[0];
            if ( raw.nodetype === 9 ) {
                return {
                    width: elem.width(),
                    height: elem.height(),
                    offset: { top: 0, left: 0 }
                };
            }
            if ( $.iswindow( raw ) ) {
                return {
                    width: elem.width(),
                    height: elem.height(),
                    offset: { top: elem.scrolltop(), left: elem.scrollleft() }
                };
            }
            if ( raw.preventdefault ) {
                return {
                    width: 0,
                    height: 0,
                    offset: { top: raw.pagey, left: raw.pagex }
                };
            }
            return {
                width: elem.outerwidth(),
                height: elem.outerheight(),
                offset: elem.offset()
            };
        }

        $.position = {
            scrollbarwidth: function() {
                if ( cachedscrollbarwidth !== undefined ) {
                    return cachedscrollbarwidth;
                }
                var w1, w2,
                    div = $( "<div style='display:block;position:absolute;width:50px;height:50px;overflow:hidden;'><div style='height:100px;width:auto;'></div></div>" ),
                    innerdiv = div.children()[0];

                $( "body" ).append( div );
                w1 = innerdiv.offsetwidth;
                div.css( "overflow", "scroll" );

                w2 = innerdiv.offsetwidth;

                if ( w1 === w2 ) {
                    w2 = div[0].clientwidth;
                }

                div.remove();

                return (cachedscrollbarwidth = w1 - w2);
            },
            getscrollinfo: function( within ) {
                var overflowx = within.iswindow || within.isdocument ? "" :
                        within.element.css( "overflow-x" ),
                    overflowy = within.iswindow || within.isdocument ? "" :
                        within.element.css( "overflow-y" ),
                    hasoverflowx = overflowx === "scroll" ||
                        ( overflowx === "auto" && within.width < within.element[0].scrollwidth ),
                    hasoverflowy = overflowy === "scroll" ||
                        ( overflowy === "auto" && within.height < within.element[0].scrollheight );
                return {
                    width: hasoverflowy ? $.position.scrollbarwidth() : 0,
                    height: hasoverflowx ? $.position.scrollbarwidth() : 0
                };
            },
            getwithininfo: function( element ) {
                var withinelement = $( element || window ),
                    iswindow = $.iswindow( withinelement[0] ),
                    isdocument = !!withinelement[ 0 ] && withinelement[ 0 ].nodetype === 9;
                return {
                    element: withinelement,
                    iswindow: iswindow,
                    isdocument: isdocument,
                    offset: withinelement.offset() || { left: 0, top: 0 },
                    scrollleft: withinelement.scrollleft(),
                    scrolltop: withinelement.scrolltop(),

                    // support: jquery 1.6.x
                    // jquery 1.6 doesn't support .outerwidth/height() on documents or windows
                    width: iswindow || isdocument ? withinelement.width() : withinelement.outerwidth(),
                    height: iswindow || isdocument ? withinelement.height() : withinelement.outerheight()
                };
            }
        };

        $.fn.position = function( options ) {
            if ( !options || !options.of ) {
                return _position.apply( this, arguments );
            }

            // make a copy, we don't want to modify arguments
            options = $.extend( {}, options );

            var atoffset, targetwidth, targetheight, targetoffset, baseposition, dimensions,
                target = $( options.of ),
                within = $.position.getwithininfo( options.within ),
                scrollinfo = $.position.getscrollinfo( within ),
                collision = ( options.collision || "flip" ).split( " " ),
                offsets = {};

            dimensions = getdimensions( target );
            if ( target[0].preventdefault ) {
                // force left top to allow flipping
                options.at = "left top";
            }
            targetwidth = dimensions.width;
            targetheight = dimensions.height;
            targetoffset = dimensions.offset;
            // clone to reuse original targetoffset later
            baseposition = $.extend( {}, targetoffset );

            // force my and at to have valid horizontal and vertical positions
            // if a value is missing or invalid, it will be converted to center
            $.each( [ "my", "at" ], function() {
                var pos = ( options[ this ] || "" ).split( " " ),
                    horizontaloffset,
                    verticaloffset;

                if ( pos.length === 1) {
                    pos = rhorizontal.test( pos[ 0 ] ) ?
                        pos.concat( [ "center" ] ) :
                        rvertical.test( pos[ 0 ] ) ?
                            [ "center" ].concat( pos ) :
                            [ "center", "center" ];
                }
                pos[ 0 ] = rhorizontal.test( pos[ 0 ] ) ? pos[ 0 ] : "center";
                pos[ 1 ] = rvertical.test( pos[ 1 ] ) ? pos[ 1 ] : "center";

                // calculate offsets
                horizontaloffset = roffset.exec( pos[ 0 ] );
                verticaloffset = roffset.exec( pos[ 1 ] );
                offsets[ this ] = [
                    horizontaloffset ? horizontaloffset[ 0 ] : 0,
                    verticaloffset ? verticaloffset[ 0 ] : 0
                ];

                // reduce to just the positions without the offsets
                options[ this ] = [
                    rposition.exec( pos[ 0 ] )[ 0 ],
                    rposition.exec( pos[ 1 ] )[ 0 ]
                ];
            });

            // normalize collision option
            if ( collision.length === 1 ) {
                collision[ 1 ] = collision[ 0 ];
            }

            if ( options.at[ 0 ] === "right" ) {
                baseposition.left += targetwidth;
            } else if ( options.at[ 0 ] === "center" ) {
                baseposition.left += targetwidth / 2;
            }

            if ( options.at[ 1 ] === "bottom" ) {
                baseposition.top += targetheight;
            } else if ( options.at[ 1 ] === "center" ) {
                baseposition.top += targetheight / 2;
            }

            atoffset = getoffsets( offsets.at, targetwidth, targetheight );
            baseposition.left += atoffset[ 0 ];
            baseposition.top += atoffset[ 1 ];

            return this.each(function() {
                var collisionposition, using,
                    elem = $( this ),
                    elemwidth = elem.outerwidth(),
                    elemheight = elem.outerheight(),
                    marginleft = parsecss( this, "marginleft" ),
                    margintop = parsecss( this, "margintop" ),
                    collisionwidth = elemwidth + marginleft + parsecss( this, "marginright" ) + scrollinfo.width,
                    collisionheight = elemheight + margintop + parsecss( this, "marginbottom" ) + scrollinfo.height,
                    position = $.extend( {}, baseposition ),
                    myoffset = getoffsets( offsets.my, elem.outerwidth(), elem.outerheight() );

                if ( options.my[ 0 ] === "right" ) {
                    position.left -= elemwidth;
                } else if ( options.my[ 0 ] === "center" ) {
                    position.left -= elemwidth / 2;
                }

                if ( options.my[ 1 ] === "bottom" ) {
                    position.top -= elemheight;
                } else if ( options.my[ 1 ] === "center" ) {
                    position.top -= elemheight / 2;
                }

                position.left += myoffset[ 0 ];
                position.top += myoffset[ 1 ];

                // if the browser doesn't support fractions, then round for consistent results
                if ( !supportsoffsetfractions ) {
                    position.left = round( position.left );
                    position.top = round( position.top );
                }

                collisionposition = {
                    marginleft: marginleft,
                    margintop: margintop
                };

                $.each( [ "left", "top" ], function( i, dir ) {
                    if ( $.ui.position[ collision[ i ] ] ) {
                        $.ui.position[ collision[ i ] ][ dir ]( position, {
                            targetwidth: targetwidth,
                            targetheight: targetheight,
                            elemwidth: elemwidth,
                            elemheight: elemheight,
                            collisionposition: collisionposition,
                            collisionwidth: collisionwidth,
                            collisionheight: collisionheight,
                            offset: [ atoffset[ 0 ] + myoffset[ 0 ], atoffset [ 1 ] + myoffset[ 1 ] ],
                            my: options.my,
                            at: options.at,
                            within: within,
                            elem: elem
                        });
                    }
                });

                if ( options.using ) {
                    // adds feedback as second argument to using callback, if present
                    using = function( props ) {
                        var left = targetoffset.left - position.left,
                            right = left + targetwidth - elemwidth,
                            top = targetoffset.top - position.top,
                            bottom = top + targetheight - elemheight,
                            feedback = {
                                target: {
                                    element: target,
                                    left: targetoffset.left,
                                    top: targetoffset.top,
                                    width: targetwidth,
                                    height: targetheight
                                },
                                element: {
                                    element: elem,
                                    left: position.left,
                                    top: position.top,
                                    width: elemwidth,
                                    height: elemheight
                                },
                                horizontal: right < 0 ? "left" : left > 0 ? "right" : "center",
                                vertical: bottom < 0 ? "top" : top > 0 ? "bottom" : "middle"
                            };
                        if ( targetwidth < elemwidth && abs( left + right ) < targetwidth ) {
                            feedback.horizontal = "center";
                        }
                        if ( targetheight < elemheight && abs( top + bottom ) < targetheight ) {
                            feedback.vertical = "middle";
                        }
                        if ( max( abs( left ), abs( right ) ) > max( abs( top ), abs( bottom ) ) ) {
                            feedback.important = "horizontal";
                        } else {
                            feedback.important = "vertical";
                        }
                        options.using.call( this, props, feedback );
                    };
                }

                elem.offset( $.extend( position, { using: using } ) );
            });
        };

        $.ui.position = {
            fit: {
                left: function( position, data ) {
                    var within = data.within,
                        withinoffset = within.iswindow ? within.scrollleft : within.offset.left,
                        outerwidth = within.width,
                        collisionposleft = position.left - data.collisionposition.marginleft,
                        overleft = withinoffset - collisionposleft,
                        overright = collisionposleft + data.collisionwidth - outerwidth - withinoffset,
                        newoverright;

                    // element is wider than within
                    if ( data.collisionwidth > outerwidth ) {
                        // element is initially over the left side of within
                        if ( overleft > 0 && overright <= 0 ) {
                            newoverright = position.left + overleft + data.collisionwidth - outerwidth - withinoffset;
                            position.left += overleft - newoverright;
                            // element is initially over right side of within
                        } else if ( overright > 0 && overleft <= 0 ) {
                            position.left = withinoffset;
                            // element is initially over both left and right sides of within
                        } else {
                            if ( overleft > overright ) {
                                position.left = withinoffset + outerwidth - data.collisionwidth;
                            } else {
                                position.left = withinoffset;
                            }
                        }
                        // too far left -> align with left edge
                    } else if ( overleft > 0 ) {
                        position.left += overleft;
                        // too far right -> align with right edge
                    } else if ( overright > 0 ) {
                        position.left -= overright;
                        // adjust based on position and margin
                    } else {
                        position.left = max( position.left - collisionposleft, position.left );
                    }
                },
                top: function( position, data ) {
                    var within = data.within,
                        withinoffset = within.iswindow ? within.scrolltop : within.offset.top,
                        outerheight = data.within.height,
                        collisionpostop = position.top - data.collisionposition.margintop,
                        overtop = withinoffset - collisionpostop,
                        overbottom = collisionpostop + data.collisionheight - outerheight - withinoffset,
                        newoverbottom;

                    // element is taller than within
                    if ( data.collisionheight > outerheight ) {
                        // element is initially over the top of within
                        if ( overtop > 0 && overbottom <= 0 ) {
                            newoverbottom = position.top + overtop + data.collisionheight - outerheight - withinoffset;
                            position.top += overtop - newoverbottom;
                            // element is initially over bottom of within
                        } else if ( overbottom > 0 && overtop <= 0 ) {
                            position.top = withinoffset;
                            // element is initially over both top and bottom of within
                        } else {
                            if ( overtop > overbottom ) {
                                position.top = withinoffset + outerheight - data.collisionheight;
                            } else {
                                position.top = withinoffset;
                            }
                        }
                        // too far up -> align with top
                    } else if ( overtop > 0 ) {
                        position.top += overtop;
                        // too far down -> align with bottom edge
                    } else if ( overbottom > 0 ) {
                        position.top -= overbottom;
                        // adjust based on position and margin
                    } else {
                        position.top = max( position.top - collisionpostop, position.top );
                    }
                }
            },
            flip: {
                left: function( position, data ) {
                    var within = data.within,
                        withinoffset = within.offset.left + within.scrollleft,
                        outerwidth = within.width,
                        offsetleft = within.iswindow ? within.scrollleft : within.offset.left,
                        collisionposleft = position.left - data.collisionposition.marginleft,
                        overleft = collisionposleft - offsetleft,
                        overright = collisionposleft + data.collisionwidth - outerwidth - offsetleft,
                        myoffset = data.my[ 0 ] === "left" ?
                            -data.elemwidth :
                                data.my[ 0 ] === "right" ?
                            data.elemwidth :
                            0,
                        atoffset = data.at[ 0 ] === "left" ?
                            data.targetwidth :
                                data.at[ 0 ] === "right" ?
                            -data.targetwidth :
                            0,
                        offset = -2 * data.offset[ 0 ],
                        newoverright,
                        newoverleft;

                    if ( overleft < 0 ) {
                        newoverright = position.left + myoffset + atoffset + offset + data.collisionwidth - outerwidth - withinoffset;
                        if ( newoverright < 0 || newoverright < abs( overleft ) ) {
                            position.left += myoffset + atoffset + offset;
                        }
                    } else if ( overright > 0 ) {
                        newoverleft = position.left - data.collisionposition.marginleft + myoffset + atoffset + offset - offsetleft;
                        if ( newoverleft > 0 || abs( newoverleft ) < overright ) {
                            position.left += myoffset + atoffset + offset;
                        }
                    }
                },
                top: function( position, data ) {
                    var within = data.within,
                        withinoffset = within.offset.top + within.scrolltop,
                        outerheight = within.height,
                        offsettop = within.iswindow ? within.scrolltop : within.offset.top,
                        collisionpostop = position.top - data.collisionposition.margintop,
                        overtop = collisionpostop - offsettop,
                        overbottom = collisionpostop + data.collisionheight - outerheight - offsettop,
                        top = data.my[ 1 ] === "top",
                        myoffset = top ?
                            -data.elemheight :
                                data.my[ 1 ] === "bottom" ?
                            data.elemheight :
                            0,
                        atoffset = data.at[ 1 ] === "top" ?
                            data.targetheight :
                                data.at[ 1 ] === "bottom" ?
                            -data.targetheight :
                            0,
                        offset = -2 * data.offset[ 1 ],
                        newovertop,
                        newoverbottom;
                    if ( overtop < 0 ) {
                        newoverbottom = position.top + myoffset + atoffset + offset + data.collisionheight - outerheight - withinoffset;
                        if ( ( position.top + myoffset + atoffset + offset) > overtop && ( newoverbottom < 0 || newoverbottom < abs( overtop ) ) ) {
                            position.top += myoffset + atoffset + offset;
                        }
                    } else if ( overbottom > 0 ) {
                        newovertop = position.top - data.collisionposition.margintop + myoffset + atoffset + offset - offsettop;
                        if ( ( position.top + myoffset + atoffset + offset) > overbottom && ( newovertop > 0 || abs( newovertop ) < overbottom ) ) {
                            position.top += myoffset + atoffset + offset;
                        }
                    }
                }
            },
            flipfit: {
                left: function() {
                    $.ui.position.flip.left.apply( this, arguments );
                    $.ui.position.fit.left.apply( this, arguments );
                },
                top: function() {
                    $.ui.position.flip.top.apply( this, arguments );
                    $.ui.position.fit.top.apply( this, arguments );
                }
            }
        };

// fraction support test
        (function() {
            var testelement, testelementparent, testelementstyle, offsetleft, i,
                body = document.getelementsbytagname( "body" )[ 0 ],
                div = document.createelement( "div" );

            //create a "fake body" for testing based on method used in jquery.support
            testelement = document.createelement( body ? "div" : "body" );
            testelementstyle = {
                visibility: "hidden",
                width: 0,
                height: 0,
                border: 0,
                margin: 0,
                background: "none"
            };
            if ( body ) {
                $.extend( testelementstyle, {
                    position: "absolute",
                    left: "-1000px",
                    top: "-1000px"
                });
            }
            for ( i in testelementstyle ) {
                testelement.style[ i ] = testelementstyle[ i ];
            }
            testelement.appendchild( div );
            testelementparent = body || document.documentelement;
            testelementparent.insertbefore( testelement, testelementparent.firstchild );

            div.style.csstext = "position: absolute; left: 10.7432222px;";

            offsetleft = $( div ).offset().left;
            supportsoffsetfractions = offsetleft > 10 && offsetleft < 11;

            testelement.innerhtml = "";
            testelementparent.removechild( testelement );
        })();

    })();

    var position = $.ui.position;


    /*!
     * jquery ui accordion 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/accordion/
     */


    var accordion = $.widget( "ui.accordion", {
        version: "1.11.2",
        options: {
            active: 0,
            animate: {},
            collapsible: false,
            event: "click",
            header: "> li > :first-child,> :not(li):even",
            heightstyle: "auto",
            icons: {
                activeheader: "ui-icon-triangle-1-s",
                header: "ui-icon-triangle-1-e"
            },

            // callbacks
            activate: null,
            beforeactivate: null
        },

        hideprops: {
            bordertopwidth: "hide",
            borderbottomwidth: "hide",
            paddingtop: "hide",
            paddingbottom: "hide",
            height: "hide"
        },

        showprops: {
            bordertopwidth: "show",
            borderbottomwidth: "show",
            paddingtop: "show",
            paddingbottom: "show",
            height: "show"
        },

        _create: function() {
            var options = this.options;
            this.prevshow = this.prevhide = $();
            this.element.addclass( "ui-accordion ui-widget ui-helper-reset" )
                // aria
                .attr( "role", "tablist" );

            // don't allow collapsible: false and active: false / null
            if ( !options.collapsible && (options.active === false || options.active == null) ) {
                options.active = 0;
            }

            this._processpanels();
            // handle negative values
            if ( options.active < 0 ) {
                options.active += this.headers.length;
            }
            this._refresh();
        },

        _getcreateeventdata: function() {
            return {
                header: this.active,
                panel: !this.active.length ? $() : this.active.next()
            };
        },

        _createicons: function() {
            var icons = this.options.icons;
            if ( icons ) {
                $( "<span>" )
                    .addclass( "ui-accordion-header-icon ui-icon " + icons.header )
                    .prependto( this.headers );
                this.active.children( ".ui-accordion-header-icon" )
                    .removeclass( icons.header )
                    .addclass( icons.activeheader );
                this.headers.addclass( "ui-accordion-icons" );
            }
        },

        _destroyicons: function() {
            this.headers
                .removeclass( "ui-accordion-icons" )
                .children( ".ui-accordion-header-icon" )
                .remove();
        },

        _destroy: function() {
            var contents;

            // clean up main element
            this.element
                .removeclass( "ui-accordion ui-widget ui-helper-reset" )
                .removeattr( "role" );

            // clean up headers
            this.headers
                .removeclass( "ui-accordion-header ui-accordion-header-active ui-state-default " +
                    "ui-corner-all ui-state-active ui-state-disabled ui-corner-top" )
                .removeattr( "role" )
                .removeattr( "aria-expanded" )
                .removeattr( "aria-selected" )
                .removeattr( "aria-controls" )
                .removeattr( "tabindex" )
                .removeuniqueid();

            this._destroyicons();

            // clean up content panels
            contents = this.headers.next()
                .removeclass( "ui-helper-reset ui-widget-content ui-corner-bottom " +
                    "ui-accordion-content ui-accordion-content-active ui-state-disabled" )
                .css( "display", "" )
                .removeattr( "role" )
                .removeattr( "aria-hidden" )
                .removeattr( "aria-labelledby" )
                .removeuniqueid();

            if ( this.options.heightstyle !== "content" ) {
                contents.css( "height", "" );
            }
        },

        _setoption: function( key, value ) {
            if ( key === "active" ) {
                // _activate() will handle invalid values and update this.options
                this._activate( value );
                return;
            }

            if ( key === "event" ) {
                if ( this.options.event ) {
                    this._off( this.headers, this.options.event );
                }
                this._setupevents( value );
            }

            this._super( key, value );

            // setting collapsible: false while collapsed; open first panel
            if ( key === "collapsible" && !value && this.options.active === false ) {
                this._activate( 0 );
            }

            if ( key === "icons" ) {
                this._destroyicons();
                if ( value ) {
                    this._createicons();
                }
            }

            // #5332 - opacity doesn't cascade to positioned elements in ie
            // so we need to add the disabled class to the headers and panels
            if ( key === "disabled" ) {
                this.element
                    .toggleclass( "ui-state-disabled", !!value )
                    .attr( "aria-disabled", value );
                this.headers.add( this.headers.next() )
                    .toggleclass( "ui-state-disabled", !!value );
            }
        },

        _keydown: function( event ) {
            if ( event.altkey || event.ctrlkey ) {
                return;
            }

            var keycode = $.ui.keycode,
                length = this.headers.length,
                currentindex = this.headers.index( event.target ),
                tofocus = false;

            switch ( event.keycode ) {
                case keycode.right:
                case keycode.down:
                    tofocus = this.headers[ ( currentindex + 1 ) % length ];
                    break;
                case keycode.left:
                case keycode.up:
                    tofocus = this.headers[ ( currentindex - 1 + length ) % length ];
                    break;
                case keycode.space:
                case keycode.enter:
                    this._eventhandler( event );
                    break;
                case keycode.home:
                    tofocus = this.headers[ 0 ];
                    break;
                case keycode.end:
                    tofocus = this.headers[ length - 1 ];
                    break;
            }

            if ( tofocus ) {
                $( event.target ).attr( "tabindex", -1 );
                $( tofocus ).attr( "tabindex", 0 );
                tofocus.focus();
                event.preventdefault();
            }
        },

        _panelkeydown: function( event ) {
            if ( event.keycode === $.ui.keycode.up && event.ctrlkey ) {
                $( event.currenttarget ).prev().focus();
            }
        },

        refresh: function() {
            var options = this.options;
            this._processpanels();

            // was collapsed or no panel
            if ( ( options.active === false && options.collapsible === true ) || !this.headers.length ) {
                options.active = false;
                this.active = $();
                // active false only when collapsible is true
            } else if ( options.active === false ) {
                this._activate( 0 );
                // was active, but active panel is gone
            } else if ( this.active.length && !$.contains( this.element[ 0 ], this.active[ 0 ] ) ) {
                // all remaining panel are disabled
                if ( this.headers.length === this.headers.find(".ui-state-disabled").length ) {
                    options.active = false;
                    this.active = $();
                    // activate previous panel
                } else {
                    this._activate( math.max( 0, options.active - 1 ) );
                }
                // was active, active panel still exists
            } else {
                // make sure active index is correct
                options.active = this.headers.index( this.active );
            }

            this._destroyicons();

            this._refresh();
        },

        _processpanels: function() {
            var prevheaders = this.headers,
                prevpanels = this.panels;

            this.headers = this.element.find( this.options.header )
                .addclass( "ui-accordion-header ui-state-default ui-corner-all" );

            this.panels = this.headers.next()
                .addclass( "ui-accordion-content ui-helper-reset ui-widget-content ui-corner-bottom" )
                .filter( ":not(.ui-accordion-content-active)" )
                .hide();

            // avoid memory leaks (#10056)
            if ( prevpanels ) {
                this._off( prevheaders.not( this.headers ) );
                this._off( prevpanels.not( this.panels ) );
            }
        },

        _refresh: function() {
            var maxheight,
                options = this.options,
                heightstyle = options.heightstyle,
                parent = this.element.parent();

            this.active = this._findactive( options.active )
                .addclass( "ui-accordion-header-active ui-state-active ui-corner-top" )
                .removeclass( "ui-corner-all" );
            this.active.next()
                .addclass( "ui-accordion-content-active" )
                .show();

            this.headers
                .attr( "role", "tab" )
                .each(function() {
                    var header = $( this ),
                        headerid = header.uniqueid().attr( "id" ),
                        panel = header.next(),
                        panelid = panel.uniqueid().attr( "id" );
                    header.attr( "aria-controls", panelid );
                    panel.attr( "aria-labelledby", headerid );
                })
                .next()
                .attr( "role", "tabpanel" );

            this.headers
                .not( this.active )
                .attr({
                    "aria-selected": "false",
                    "aria-expanded": "false",
                    tabindex: -1
                })
                .next()
                .attr({
                    "aria-hidden": "true"
                })
                .hide();

            // make sure at least one header is in the tab order
            if ( !this.active.length ) {
                this.headers.eq( 0 ).attr( "tabindex", 0 );
            } else {
                this.active.attr({
                    "aria-selected": "true",
                    "aria-expanded": "true",
                    tabindex: 0
                })
                    .next()
                    .attr({
                        "aria-hidden": "false"
                    });
            }

            this._createicons();

            this._setupevents( options.event );

            if ( heightstyle === "fill" ) {
                maxheight = parent.height();
                this.element.siblings( ":visible" ).each(function() {
                    var elem = $( this ),
                        position = elem.css( "position" );

                    if ( position === "absolute" || position === "fixed" ) {
                        return;
                    }
                    maxheight -= elem.outerheight( true );
                });

                this.headers.each(function() {
                    maxheight -= $( this ).outerheight( true );
                });

                this.headers.next()
                    .each(function() {
                        $( this ).height( math.max( 0, maxheight -
                            $( this ).innerheight() + $( this ).height() ) );
                    })
                    .css( "overflow", "auto" );
            } else if ( heightstyle === "auto" ) {
                maxheight = 0;
                this.headers.next()
                    .each(function() {
                        maxheight = math.max( maxheight, $( this ).css( "height", "" ).height() );
                    })
                    .height( maxheight );
            }
        },

        _activate: function( index ) {
            var active = this._findactive( index )[ 0 ];

            // trying to activate the already active panel
            if ( active === this.active[ 0 ] ) {
                return;
            }

            // trying to collapse, simulate a click on the currently active header
            active = active || this.active[ 0 ];

            this._eventhandler({
                target: active,
                currenttarget: active,
                preventdefault: $.noop
            });
        },

        _findactive: function( selector ) {
            return typeof selector === "number" ? this.headers.eq( selector ) : $();
        },

        _setupevents: function( event ) {
            var events = {
                keydown: "_keydown"
            };
            if ( event ) {
                $.each( event.split( " " ), function( index, eventname ) {
                    events[ eventname ] = "_eventhandler";
                });
            }

            this._off( this.headers.add( this.headers.next() ) );
            this._on( this.headers, events );
            this._on( this.headers.next(), { keydown: "_panelkeydown" });
            this._hoverable( this.headers );
            this._focusable( this.headers );
        },

        _eventhandler: function( event ) {
            var options = this.options,
                active = this.active,
                clicked = $( event.currenttarget ),
                clickedisactive = clicked[ 0 ] === active[ 0 ],
                collapsing = clickedisactive && options.collapsible,
                toshow = collapsing ? $() : clicked.next(),
                tohide = active.next(),
                eventdata = {
                    oldheader: active,
                    oldpanel: tohide,
                    newheader: collapsing ? $() : clicked,
                    newpanel: toshow
                };

            event.preventdefault();

            if (
            // click on active header, but not collapsible
                ( clickedisactive && !options.collapsible ) ||
                // allow canceling activation
                ( this._trigger( "beforeactivate", event, eventdata ) === false ) ) {
                return;
            }

            options.active = collapsing ? false : this.headers.index( clicked );

            // when the call to ._toggle() comes after the class changes
            // it causes a very odd bug in ie 8 (see #6720)
            this.active = clickedisactive ? $() : clicked;
            this._toggle( eventdata );

            // switch classes
            // corner classes on the previously active header stay after the animation
            active.removeclass( "ui-accordion-header-active ui-state-active" );
            if ( options.icons ) {
                active.children( ".ui-accordion-header-icon" )
                    .removeclass( options.icons.activeheader )
                    .addclass( options.icons.header );
            }

            if ( !clickedisactive ) {
                clicked
                    .removeclass( "ui-corner-all" )
                    .addclass( "ui-accordion-header-active ui-state-active ui-corner-top" );
                if ( options.icons ) {
                    clicked.children( ".ui-accordion-header-icon" )
                        .removeclass( options.icons.header )
                        .addclass( options.icons.activeheader );
                }

                clicked
                    .next()
                    .addclass( "ui-accordion-content-active" );
            }
        },

        _toggle: function( data ) {
            var toshow = data.newpanel,
                tohide = this.prevshow.length ? this.prevshow : data.oldpanel;

            // handle activating a panel during the animation for another activation
            this.prevshow.add( this.prevhide ).stop( true, true );
            this.prevshow = toshow;
            this.prevhide = tohide;

            if ( this.options.animate ) {
                this._animate( toshow, tohide, data );
            } else {
                tohide.hide();
                toshow.show();
                this._togglecomplete( data );
            }

            tohide.attr({
                "aria-hidden": "true"
            });
            tohide.prev().attr( "aria-selected", "false" );
            // if we're switching panels, remove the old header from the tab order
            // if we're opening from collapsed state, remove the previous header from the tab order
            // if we're collapsing, then keep the collapsing header in the tab order
            if ( toshow.length && tohide.length ) {
                tohide.prev().attr({
                    "tabindex": -1,
                    "aria-expanded": "false"
                });
            } else if ( toshow.length ) {
                this.headers.filter(function() {
                    return $( this ).attr( "tabindex" ) === 0;
                })
                    .attr( "tabindex", -1 );
            }

            toshow
                .attr( "aria-hidden", "false" )
                .prev()
                .attr({
                    "aria-selected": "true",
                    tabindex: 0,
                    "aria-expanded": "true"
                });
        },

        _animate: function( toshow, tohide, data ) {
            var total, easing, duration,
                that = this,
                adjust = 0,
                down = toshow.length &&
                    ( !tohide.length || ( toshow.index() < tohide.index() ) ),
                animate = this.options.animate || {},
                options = down && animate.down || animate,
                complete = function() {
                    that._togglecomplete( data );
                };

            if ( typeof options === "number" ) {
                duration = options;
            }
            if ( typeof options === "string" ) {
                easing = options;
            }
            // fall back from options to animation in case of partial down settings
            easing = easing || options.easing || animate.easing;
            duration = duration || options.duration || animate.duration;

            if ( !tohide.length ) {
                return toshow.animate( this.showprops, duration, easing, complete );
            }
            if ( !toshow.length ) {
                return tohide.animate( this.hideprops, duration, easing, complete );
            }

            total = toshow.show().outerheight();
            tohide.animate( this.hideprops, {
                duration: duration,
                easing: easing,
                step: function( now, fx ) {
                    fx.now = math.round( now );
                }
            });
            toshow
                .hide()
                .animate( this.showprops, {
                    duration: duration,
                    easing: easing,
                    complete: complete,
                    step: function( now, fx ) {
                        fx.now = math.round( now );
                        if ( fx.prop !== "height" ) {
                            adjust += fx.now;
                        } else if ( that.options.heightstyle !== "content" ) {
                            fx.now = math.round( total - tohide.outerheight() - adjust );
                            adjust = 0;
                        }
                    }
                });
        },

        _togglecomplete: function( data ) {
            var tohide = data.oldpanel;

            tohide
                .removeclass( "ui-accordion-content-active" )
                .prev()
                .removeclass( "ui-corner-top" )
                .addclass( "ui-corner-all" );

            // work around for rendering bug in ie (#5421)
            if ( tohide.length ) {
                tohide.parent()[ 0 ].classname = tohide.parent()[ 0 ].classname;
            }
            this._trigger( "activate", null, data );
        }
    });


    /*!
     * jquery ui menu 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/menu/
     */


    var menu = $.widget( "ui.menu", {
        version: "1.11.2",
        defaultelement: "<ul>",
        delay: 300,
        options: {
            icons: {
                submenu: "ui-icon-carat-1-e"
            },
            items: "> *",
            menus: "ul",
            position: {
                my: "left-1 top",
                at: "right top"
            },
            role: "menu",

            // callbacks
            blur: null,
            focus: null,
            select: null
        },

        _create: function() {
            this.activemenu = this.element;

            // flag used to prevent firing of the click handler
            // as the event bubbles up through nested menus
            this.mousehandled = false;
            this.element
                .uniqueid()
                .addclass( "ui-menu ui-widget ui-widget-content" )
                .toggleclass( "ui-menu-icons", !!this.element.find( ".ui-icon" ).length )
                .attr({
                    role: this.options.role,
                    tabindex: 0
                });

            if ( this.options.disabled ) {
                this.element
                    .addclass( "ui-state-disabled" )
                    .attr( "aria-disabled", "true" );
            }

            this._on({
                // prevent focus from sticking to links inside menu after clicking
                // them (focus should always stay on ul during navigation).
                "mousedown .ui-menu-item": function( event ) {
                    event.preventdefault();
                },
                "click .ui-menu-item": function( event ) {
                    var target = $( event.target );
                    if ( !this.mousehandled && target.not( ".ui-state-disabled" ).length ) {
                        this.select( event );

                        // only set the mousehandled flag if the event will bubble, see #9469.
                        if ( !event.ispropagationstopped() ) {
                            this.mousehandled = true;
                        }

                        // open submenu on click
                        if ( target.has( ".ui-menu" ).length ) {
                            this.expand( event );
                        } else if ( !this.element.is( ":focus" ) && $( this.document[ 0 ].activeelement ).closest( ".ui-menu" ).length ) {

                            // redirect focus to the menu
                            this.element.trigger( "focus", [ true ] );

                            // if the active item is on the top level, let it stay active.
                            // otherwise, blur the active item since it is no longer visible.
                            if ( this.active && this.active.parents( ".ui-menu" ).length === 1 ) {
                                cleartimeout( this.timer );
                            }
                        }
                    }
                },
                "mouseenter .ui-menu-item": function( event ) {
                    // ignore mouse events while typeahead is active, see #10458.
                    // prevents focusing the wrong item when typeahead causes a scroll while the mouse
                    // is over an item in the menu
                    if ( this.previousfilter ) {
                        return;
                    }
                    var target = $( event.currenttarget );
                    // remove ui-state-active class from siblings of the newly focused menu item
                    // to avoid a jump caused by adjacent elements both having a class with a border
                    target.siblings( ".ui-state-active" ).removeclass( "ui-state-active" );
                    this.focus( event, target );
                },
                mouseleave: "collapseall",
                "mouseleave .ui-menu": "collapseall",
                focus: function( event, keepactiveitem ) {
                    // if there's already an active item, keep it active
                    // if not, activate the first item
                    var item = this.active || this.element.find( this.options.items ).eq( 0 );

                    if ( !keepactiveitem ) {
                        this.focus( event, item );
                    }
                },
                blur: function( event ) {
                    this._delay(function() {
                        if ( !$.contains( this.element[0], this.document[0].activeelement ) ) {
                            this.collapseall( event );
                        }
                    });
                },
                keydown: "_keydown"
            });

            this.refresh();

            // clicks outside of a menu collapse any open menus
            this._on( this.document, {
                click: function( event ) {
                    if ( this._closeondocumentclick( event ) ) {
                        this.collapseall( event );
                    }

                    // reset the mousehandled flag
                    this.mousehandled = false;
                }
            });
        },

        _destroy: function() {
            // destroy (sub)menus
            this.element
                .removeattr( "aria-activedescendant" )
                .find( ".ui-menu" ).addback()
                .removeclass( "ui-menu ui-widget ui-widget-content ui-menu-icons ui-front" )
                .removeattr( "role" )
                .removeattr( "tabindex" )
                .removeattr( "aria-labelledby" )
                .removeattr( "aria-expanded" )
                .removeattr( "aria-hidden" )
                .removeattr( "aria-disabled" )
                .removeuniqueid()
                .show();

            // destroy menu items
            this.element.find( ".ui-menu-item" )
                .removeclass( "ui-menu-item" )
                .removeattr( "role" )
                .removeattr( "aria-disabled" )
                .removeuniqueid()
                .removeclass( "ui-state-hover" )
                .removeattr( "tabindex" )
                .removeattr( "role" )
                .removeattr( "aria-haspopup" )
                .children().each( function() {
                    var elem = $( this );
                    if ( elem.data( "ui-menu-submenu-carat" ) ) {
                        elem.remove();
                    }
                });

            // destroy menu dividers
            this.element.find( ".ui-menu-divider" ).removeclass( "ui-menu-divider ui-widget-content" );
        },

        _keydown: function( event ) {
            var match, prev, character, skip,
                preventdefault = true;

            switch ( event.keycode ) {
                case $.ui.keycode.page_up:
                    this.previouspage( event );
                    break;
                case $.ui.keycode.page_down:
                    this.nextpage( event );
                    break;
                case $.ui.keycode.home:
                    this._move( "first", "first", event );
                    break;
                case $.ui.keycode.end:
                    this._move( "last", "last", event );
                    break;
                case $.ui.keycode.up:
                    this.previous( event );
                    break;
                case $.ui.keycode.down:
                    this.next( event );
                    break;
                case $.ui.keycode.left:
                    this.collapse( event );
                    break;
                case $.ui.keycode.right:
                    if ( this.active && !this.active.is( ".ui-state-disabled" ) ) {
                        this.expand( event );
                    }
                    break;
                case $.ui.keycode.enter:
                case $.ui.keycode.space:
                    this._activate( event );
                    break;
                case $.ui.keycode.escape:
                    this.collapse( event );
                    break;
                default:
                    preventdefault = false;
                    prev = this.previousfilter || "";
                    character = string.fromcharcode( event.keycode );
                    skip = false;

                    cleartimeout( this.filtertimer );

                    if ( character === prev ) {
                        skip = true;
                    } else {
                        character = prev + character;
                    }

                    match = this._filtermenuitems( character );
                    match = skip && match.index( this.active.next() ) !== -1 ?
                        this.active.nextall( ".ui-menu-item" ) :
                        match;

                    // if no matches on the current filter, reset to the last character pressed
                    // to move down the menu to the first item that starts with that character
                    if ( !match.length ) {
                        character = string.fromcharcode( event.keycode );
                        match = this._filtermenuitems( character );
                    }

                    if ( match.length ) {
                        this.focus( event, match );
                        this.previousfilter = character;
                        this.filtertimer = this._delay(function() {
                            delete this.previousfilter;
                        }, 1000 );
                    } else {
                        delete this.previousfilter;
                    }
            }

            if ( preventdefault ) {
                event.preventdefault();
            }
        },

        _activate: function( event ) {
            if ( !this.active.is( ".ui-state-disabled" ) ) {
                if ( this.active.is( "[aria-haspopup='true']" ) ) {
                    this.expand( event );
                } else {
                    this.select( event );
                }
            }
        },

        refresh: function() {
            var menus, items,
                that = this,
                icon = this.options.icons.submenu,
                submenus = this.element.find( this.options.menus );

            this.element.toggleclass( "ui-menu-icons", !!this.element.find( ".ui-icon" ).length );

            // initialize nested menus
            submenus.filter( ":not(.ui-menu)" )
                .addclass( "ui-menu ui-widget ui-widget-content ui-front" )
                .hide()
                .attr({
                    role: this.options.role,
                    "aria-hidden": "true",
                    "aria-expanded": "false"
                })
                .each(function() {
                    var menu = $( this ),
                        item = menu.parent(),
                        submenucarat = $( "<span>" )
                            .addclass( "ui-menu-icon ui-icon " + icon )
                            .data( "ui-menu-submenu-carat", true );

                    item
                        .attr( "aria-haspopup", "true" )
                        .prepend( submenucarat );
                    menu.attr( "aria-labelledby", item.attr( "id" ) );
                });

            menus = submenus.add( this.element );
            items = menus.find( this.options.items );

            // initialize menu-items containing spaces and/or dashes only as dividers
            items.not( ".ui-menu-item" ).each(function() {
                var item = $( this );
                if ( that._isdivider( item ) ) {
                    item.addclass( "ui-widget-content ui-menu-divider" );
                }
            });

            // don't refresh list items that are already adapted
            items.not( ".ui-menu-item, .ui-menu-divider" )
                .addclass( "ui-menu-item" )
                .uniqueid()
                .attr({
                    tabindex: -1,
                    role: this._itemrole()
                });

            // add aria-disabled attribute to any disabled menu item
            items.filter( ".ui-state-disabled" ).attr( "aria-disabled", "true" );

            // if the active item has been removed, blur the menu
            if ( this.active && !$.contains( this.element[ 0 ], this.active[ 0 ] ) ) {
                this.blur();
            }
        },

        _itemrole: function() {
            return {
                menu: "menuitem",
                listbox: "option"
            }[ this.options.role ];
        },

        _setoption: function( key, value ) {
            if ( key === "icons" ) {
                this.element.find( ".ui-menu-icon" )
                    .removeclass( this.options.icons.submenu )
                    .addclass( value.submenu );
            }
            if ( key === "disabled" ) {
                this.element
                    .toggleclass( "ui-state-disabled", !!value )
                    .attr( "aria-disabled", value );
            }
            this._super( key, value );
        },

        focus: function( event, item ) {
            var nested, focused;
            this.blur( event, event && event.type === "focus" );

            this._scrollintoview( item );

            this.active = item.first();
            focused = this.active.addclass( "ui-state-focus" ).removeclass( "ui-state-active" );
            // only update aria-activedescendant if there's a role
            // otherwise we assume focus is managed elsewhere
            if ( this.options.role ) {
                this.element.attr( "aria-activedescendant", focused.attr( "id" ) );
            }

            // highlight active parent menu item, if any
            this.active
                .parent()
                .closest( ".ui-menu-item" )
                .addclass( "ui-state-active" );

            if ( event && event.type === "keydown" ) {
                this._close();
            } else {
                this.timer = this._delay(function() {
                    this._close();
                }, this.delay );
            }

            nested = item.children( ".ui-menu" );
            if ( nested.length && event && ( /^mouse/.test( event.type ) ) ) {
                this._startopening(nested);
            }
            this.activemenu = item.parent();

            this._trigger( "focus", event, { item: item } );
        },

        _scrollintoview: function( item ) {
            var bordertop, paddingtop, offset, scroll, elementheight, itemheight;
            if ( this._hasscroll() ) {
                bordertop = parsefloat( $.css( this.activemenu[0], "bordertopwidth" ) ) || 0;
                paddingtop = parsefloat( $.css( this.activemenu[0], "paddingtop" ) ) || 0;
                offset = item.offset().top - this.activemenu.offset().top - bordertop - paddingtop;
                scroll = this.activemenu.scrolltop();
                elementheight = this.activemenu.height();
                itemheight = item.outerheight();

                if ( offset < 0 ) {
                    this.activemenu.scrolltop( scroll + offset );
                } else if ( offset + itemheight > elementheight ) {
                    this.activemenu.scrolltop( scroll + offset - elementheight + itemheight );
                }
            }
        },

        blur: function( event, fromfocus ) {
            if ( !fromfocus ) {
                cleartimeout( this.timer );
            }

            if ( !this.active ) {
                return;
            }

            this.active.removeclass( "ui-state-focus" );
            this.active = null;

            this._trigger( "blur", event, { item: this.active } );
        },

        _startopening: function( submenu ) {
            cleartimeout( this.timer );

            // don't open if already open fixes a firefox bug that caused a .5 pixel
            // shift in the submenu position when mousing over the carat icon
            if ( submenu.attr( "aria-hidden" ) !== "true" ) {
                return;
            }

            this.timer = this._delay(function() {
                this._close();
                this._open( submenu );
            }, this.delay );
        },

        _open: function( submenu ) {
            var position = $.extend({
                of: this.active
            }, this.options.position );

            cleartimeout( this.timer );
            this.element.find( ".ui-menu" ).not( submenu.parents( ".ui-menu" ) )
                .hide()
                .attr( "aria-hidden", "true" );

            submenu
                .show()
                .removeattr( "aria-hidden" )
                .attr( "aria-expanded", "true" )
                .position( position );
        },

        collapseall: function( event, all ) {
            cleartimeout( this.timer );
            this.timer = this._delay(function() {
                // if we were passed an event, look for the submenu that contains the event
                var currentmenu = all ? this.element :
                    $( event && event.target ).closest( this.element.find( ".ui-menu" ) );

                // if we found no valid submenu ancestor, use the main menu to close all sub menus anyway
                if ( !currentmenu.length ) {
                    currentmenu = this.element;
                }

                this._close( currentmenu );

                this.blur( event );
                this.activemenu = currentmenu;
            }, this.delay );
        },

        // with no arguments, closes the currently active menu - if nothing is active
        // it closes all menus.  if passed an argument, it will search for menus below
        _close: function( startmenu ) {
            if ( !startmenu ) {
                startmenu = this.active ? this.active.parent() : this.element;
            }

            startmenu
                .find( ".ui-menu" )
                .hide()
                .attr( "aria-hidden", "true" )
                .attr( "aria-expanded", "false" )
                .end()
                .find( ".ui-state-active" ).not( ".ui-state-focus" )
                .removeclass( "ui-state-active" );
        },

        _closeondocumentclick: function( event ) {
            return !$( event.target ).closest( ".ui-menu" ).length;
        },

        _isdivider: function( item ) {

            // match hyphen, em dash, en dash
            return !/[^\-\u2014\u2013\s]/.test( item.text() );
        },

        collapse: function( event ) {
            var newitem = this.active &&
                this.active.parent().closest( ".ui-menu-item", this.element );
            if ( newitem && newitem.length ) {
                this._close();
                this.focus( event, newitem );
            }
        },

        expand: function( event ) {
            var newitem = this.active &&
                this.active
                    .children( ".ui-menu " )
                    .find( this.options.items )
                    .first();

            if ( newitem && newitem.length ) {
                this._open( newitem.parent() );

                // delay so firefox will not hide activedescendant change in expanding submenu from at
                this._delay(function() {
                    this.focus( event, newitem );
                });
            }
        },

        next: function( event ) {
            this._move( "next", "first", event );
        },

        previous: function( event ) {
            this._move( "prev", "last", event );
        },

        isfirstitem: function() {
            return this.active && !this.active.prevall( ".ui-menu-item" ).length;
        },

        islastitem: function() {
            return this.active && !this.active.nextall( ".ui-menu-item" ).length;
        },

        _move: function( direction, filter, event ) {
            var next;
            if ( this.active ) {
                if ( direction === "first" || direction === "last" ) {
                    next = this.active
                        [ direction === "first" ? "prevall" : "nextall" ]( ".ui-menu-item" )
                        .eq( -1 );
                } else {
                    next = this.active
                        [ direction + "all" ]( ".ui-menu-item" )
                        .eq( 0 );
                }
            }
            if ( !next || !next.length || !this.active ) {
                next = this.activemenu.find( this.options.items )[ filter ]();
            }

            this.focus( event, next );
        },

        nextpage: function( event ) {
            var item, base, height;

            if ( !this.active ) {
                this.next( event );
                return;
            }
            if ( this.islastitem() ) {
                return;
            }
            if ( this._hasscroll() ) {
                base = this.active.offset().top;
                height = this.element.height();
                this.active.nextall( ".ui-menu-item" ).each(function() {
                    item = $( this );
                    return item.offset().top - base - height < 0;
                });

                this.focus( event, item );
            } else {
                this.focus( event, this.activemenu.find( this.options.items )
                    [ !this.active ? "first" : "last" ]() );
            }
        },

        previouspage: function( event ) {
            var item, base, height;
            if ( !this.active ) {
                this.next( event );
                return;
            }
            if ( this.isfirstitem() ) {
                return;
            }
            if ( this._hasscroll() ) {
                base = this.active.offset().top;
                height = this.element.height();
                this.active.prevall( ".ui-menu-item" ).each(function() {
                    item = $( this );
                    return item.offset().top - base + height > 0;
                });

                this.focus( event, item );
            } else {
                this.focus( event, this.activemenu.find( this.options.items ).first() );
            }
        },

        _hasscroll: function() {
            return this.element.outerheight() < this.element.prop( "scrollheight" );
        },

        select: function( event ) {
            // todo: it should never be possible to not have an active item at this
            // point, but the tests don't trigger mouseenter before click.
            this.active = this.active || $( event.target ).closest( ".ui-menu-item" );
            var ui = { item: this.active };
            if ( !this.active.has( ".ui-menu" ).length ) {
                this.collapseall( event, true );
            }
            this._trigger( "select", event, ui );
        },

        _filtermenuitems: function(character) {
            var escapedcharacter = character.replace( /[\-\[\]{}()*+?.,\\\^$|#\s]/g, "\\$&" ),
                regex = new regexp( "^" + escapedcharacter, "i" );

            return this.activemenu
                .find( this.options.items )

                // only match on items, not dividers or other content (#10571)
                .filter( ".ui-menu-item" )
                .filter(function() {
                    return regex.test( $.trim( $( this ).text() ) );
                });
        }
    });


    /*!
     * jquery ui autocomplete 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/autocomplete/
     */


    $.widget( "ui.autocomplete", {
        version: "1.11.2",
        defaultelement: "<input>",
        options: {
            appendto: null,
            autofocus: false,
            delay: 300,
            minlength: 1,
            position: {
                my: "left top",
                at: "left bottom",
                collision: "none"
            },
            source: null,

            // callbacks
            change: null,
            close: null,
            focus: null,
            open: null,
            response: null,
            search: null,
            select: null
        },

        requestindex: 0,
        pending: 0,

        _create: function() {
            // some browsers only repeat keydown events, not keypress events,
            // so we use the suppresskeypress flag to determine if we've already
            // handled the keydown event. #7269
            // unfortunately the code for & in keypress is the same as the up arrow,
            // so we use the suppresskeypressrepeat flag to avoid handling keypress
            // events when we know the keydown event was used to modify the
            // search term. #7799
            var suppresskeypress, suppresskeypressrepeat, suppressinput,
                nodename = this.element[ 0 ].nodename.tolowercase(),
                istextarea = nodename === "textarea",
                isinput = nodename === "input";

            this.ismultiline =
                // textareas are always multi-line
                istextarea ? true :
                    // inputs are always single-line, even if inside a contenteditable element
                    // ie also treats inputs as contenteditable
                    isinput ? false :
                        // all other element types are determined by whether or not they're contenteditable
                        this.element.prop( "iscontenteditable" );

            this.valuemethod = this.element[ istextarea || isinput ? "val" : "text" ];
            this.isnewmenu = true;

            this.element
                .addclass( "ui-autocomplete-input" )
                .attr( "autocomplete", "off" );

            this._on( this.element, {
                keydown: function( event ) {
                    if ( this.element.prop( "readonly" ) ) {
                        suppresskeypress = true;
                        suppressinput = true;
                        suppresskeypressrepeat = true;
                        return;
                    }

                    suppresskeypress = false;
                    suppressinput = false;
                    suppresskeypressrepeat = false;
                    var keycode = $.ui.keycode;
                    switch ( event.keycode ) {
                        case keycode.page_up:
                            suppresskeypress = true;
                            this._move( "previouspage", event );
                            break;
                        case keycode.page_down:
                            suppresskeypress = true;
                            this._move( "nextpage", event );
                            break;
                        case keycode.up:
                            suppresskeypress = true;
                            this._keyevent( "previous", event );
                            break;
                        case keycode.down:
                            suppresskeypress = true;
                            this._keyevent( "next", event );
                            break;
                        case keycode.enter:
                            // when menu is open and has focus
                            if ( this.menu.active ) {
                                // #6055 - opera still allows the keypress to occur
                                // which causes forms to submit
                                suppresskeypress = true;
                                event.preventdefault();
                                this.menu.select( event );
                            }
                            break;
                        case keycode.tab:
                            if ( this.menu.active ) {
                                this.menu.select( event );
                            }
                            break;
                        case keycode.escape:
                            if ( this.menu.element.is( ":visible" ) ) {
                                if ( !this.ismultiline ) {
                                    this._value( this.term );
                                }
                                this.close( event );
                                // different browsers have different default behavior for escape
                                // single press can mean undo or clear
                                // double press in ie means clear the whole form
                                event.preventdefault();
                            }
                            break;
                        default:
                            suppresskeypressrepeat = true;
                            // search timeout should be triggered before the input value is changed
                            this._searchtimeout( event );
                            break;
                    }
                },
                keypress: function( event ) {
                    if ( suppresskeypress ) {
                        suppresskeypress = false;
                        if ( !this.ismultiline || this.menu.element.is( ":visible" ) ) {
                            event.preventdefault();
                        }
                        return;
                    }
                    if ( suppresskeypressrepeat ) {
                        return;
                    }

                    // replicate some key handlers to allow them to repeat in firefox and opera
                    var keycode = $.ui.keycode;
                    switch ( event.keycode ) {
                        case keycode.page_up:
                            this._move( "previouspage", event );
                            break;
                        case keycode.page_down:
                            this._move( "nextpage", event );
                            break;
                        case keycode.up:
                            this._keyevent( "previous", event );
                            break;
                        case keycode.down:
                            this._keyevent( "next", event );
                            break;
                    }
                },
                input: function( event ) {
                    if ( suppressinput ) {
                        suppressinput = false;
                        event.preventdefault();
                        return;
                    }
                    this._searchtimeout( event );
                },
                focus: function() {
                    this.selecteditem = null;
                    this.previous = this._value();
                },
                blur: function( event ) {
                    if ( this.cancelblur ) {
                        delete this.cancelblur;
                        return;
                    }

                    cleartimeout( this.searching );
                    this.close( event );
                    this._change( event );
                }
            });

            this._initsource();
            this.menu = $( "<ul>" )
                .addclass( "ui-autocomplete ui-front" )
                .appendto( this._appendto() )
                .menu({
                    // disable aria support, the live region takes care of that
                    role: null
                })
                .hide()
                .menu( "instance" );

            this._on( this.menu.element, {
                mousedown: function( event ) {
                    // prevent moving focus out of the text field
                    event.preventdefault();

                    // ie doesn't prevent moving focus even with event.preventdefault()
                    // so we set a flag to know when we should ignore the blur event
                    this.cancelblur = true;
                    this._delay(function() {
                        delete this.cancelblur;
                    });

                    // clicking on the scrollbar causes focus to shift to the body
                    // but we can't detect a mouseup or a click immediately afterward
                    // so we have to track the next mousedown and close the menu if
                    // the user clicks somewhere outside of the autocomplete
                    var menuelement = this.menu.element[ 0 ];
                    if ( !$( event.target ).closest( ".ui-menu-item" ).length ) {
                        this._delay(function() {
                            var that = this;
                            this.document.one( "mousedown", function( event ) {
                                if ( event.target !== that.element[ 0 ] &&
                                    event.target !== menuelement &&
                                    !$.contains( menuelement, event.target ) ) {
                                    that.close();
                                }
                            });
                        });
                    }
                },
                menufocus: function( event, ui ) {
                    var label, item;
                    // support: firefox
                    // prevent accidental activation of menu items in firefox (#7024 #9118)
                    if ( this.isnewmenu ) {
                        this.isnewmenu = false;
                        if ( event.originalevent && /^mouse/.test( event.originalevent.type ) ) {
                            this.menu.blur();

                            this.document.one( "mousemove", function() {
                                $( event.target ).trigger( event.originalevent );
                            });

                            return;
                        }
                    }

                    item = ui.item.data( "ui-autocomplete-item" );
                    if ( false !== this._trigger( "focus", event, { item: item } ) ) {
                        // use value to match what will end up in the input, if it was a key event
                        if ( event.originalevent && /^key/.test( event.originalevent.type ) ) {
                            this._value( item.value );
                        }
                    }

                    // announce the value in the liveregion
                    label = ui.item.attr( "aria-label" ) || item.value;
                    if ( label && $.trim( label ).length ) {
                        this.liveregion.children().hide();
                        $( "<div>" ).text( label ).appendto( this.liveregion );
                    }
                },
                menuselect: function( event, ui ) {
                    var item = ui.item.data( "ui-autocomplete-item" ),
                        previous = this.previous;

                    // only trigger when focus was lost (click on menu)
                    if ( this.element[ 0 ] !== this.document[ 0 ].activeelement ) {
                        this.element.focus();
                        this.previous = previous;
                        // #6109 - ie triggers two focus events and the second
                        // is asynchronous, so we need to reset the previous
                        // term synchronously and asynchronously :-(
                        this._delay(function() {
                            this.previous = previous;
                            this.selecteditem = item;
                        });
                    }

                    if ( false !== this._trigger( "select", event, { item: item } ) ) {
                        this._value( item.value );
                    }
                    // reset the term after the select event
                    // this allows custom select handling to work properly
                    this.term = this._value();

                    this.close( event );
                    this.selecteditem = item;
                }
            });

            this.liveregion = $( "<span>", {
                role: "status",
                "aria-live": "assertive",
                "aria-relevant": "additions"
            })
                .addclass( "ui-helper-hidden-accessible" )
                .appendto( this.document[ 0 ].body );

            // turning off autocomplete prevents the browser from remembering the
            // value when navigating through history, so we re-enable autocomplete
            // if the page is unloaded before the widget is destroyed. #7790
            this._on( this.window, {
                beforeunload: function() {
                    this.element.removeattr( "autocomplete" );
                }
            });
        },

        _destroy: function() {
            cleartimeout( this.searching );
            this.element
                .removeclass( "ui-autocomplete-input" )
                .removeattr( "autocomplete" );
            this.menu.element.remove();
            this.liveregion.remove();
        },

        _setoption: function( key, value ) {
            this._super( key, value );
            if ( key === "source" ) {
                this._initsource();
            }
            if ( key === "appendto" ) {
                this.menu.element.appendto( this._appendto() );
            }
            if ( key === "disabled" && value && this.xhr ) {
                this.xhr.abort();
            }
        },

        _appendto: function() {
            var element = this.options.appendto;

            if ( element ) {
                element = element.jquery || element.nodetype ?
                    $( element ) :
                    this.document.find( element ).eq( 0 );
            }

            if ( !element || !element[ 0 ] ) {
                element = this.element.closest( ".ui-front" );
            }

            if ( !element.length ) {
                element = this.document[ 0 ].body;
            }

            return element;
        },

        _initsource: function() {
            var array, url,
                that = this;
            if ( $.isarray( this.options.source ) ) {
                array = this.options.source;
                this.source = function( request, response ) {
                    response( $.ui.autocomplete.filter( array, request.term ) );
                };
            } else if ( typeof this.options.source === "string" ) {
                url = this.options.source;
                this.source = function( request, response ) {
                    if ( that.xhr ) {
                        that.xhr.abort();
                    }
                    that.xhr = $.ajax({
                        url: url,
                        data: request,
                        datatype: "json",
                        success: function( data ) {
                            response( data );
                        },
                        error: function() {
                            response([]);
                        }
                    });
                };
            } else {
                this.source = this.options.source;
            }
        },

        _searchtimeout: function( event ) {
            cleartimeout( this.searching );
            this.searching = this._delay(function() {

                // search if the value has changed, or if the user retypes the same value (see #7434)
                var equalvalues = this.term === this._value(),
                    menuvisible = this.menu.element.is( ":visible" ),
                    modifierkey = event.altkey || event.ctrlkey || event.metakey || event.shiftkey;

                if ( !equalvalues || ( equalvalues && !menuvisible && !modifierkey ) ) {
                    this.selecteditem = null;
                    this.search( null, event );
                }
            }, this.options.delay );
        },

        search: function( value, event ) {
            value = value != null ? value : this._value();

            // always save the actual value, not the one passed as an argument
            this.term = this._value();

            if ( value.length < this.options.minlength ) {
                return this.close( event );
            }

            if ( this._trigger( "search", event ) === false ) {
                return;
            }

            return this._search( value );
        },

        _search: function( value ) {
            this.pending++;
            this.element.addclass( "ui-autocomplete-loading" );
            this.cancelsearch = false;

            this.source( { term: value }, this._response() );
        },

        _response: function() {
            var index = ++this.requestindex;

            return $.proxy(function( content ) {
                if ( index === this.requestindex ) {
                    this.__response( content );
                }

                this.pending--;
                if ( !this.pending ) {
                    this.element.removeclass( "ui-autocomplete-loading" );
                }
            }, this );
        },

        __response: function( content ) {
            if ( content ) {
                content = this._normalize( content );
            }
            this._trigger( "response", null, { content: content } );
            if ( !this.options.disabled && content && content.length && !this.cancelsearch ) {
                this._suggest( content );
                this._trigger( "open" );
            } else {
                // use ._close() instead of .close() so we don't cancel future searches
                this._close();
            }
        },

        close: function( event ) {
            this.cancelsearch = true;
            this._close( event );
        },

        _close: function( event ) {
            if ( this.menu.element.is( ":visible" ) ) {
                this.menu.element.hide();
                this.menu.blur();
                this.isnewmenu = true;
                this._trigger( "close", event );
            }
        },

        _change: function( event ) {
            if ( this.previous !== this._value() ) {
                this._trigger( "change", event, { item: this.selecteditem } );
            }
        },

        _normalize: function( items ) {
            // assume all items have the right format when the first item is complete
            if ( items.length && items[ 0 ].label && items[ 0 ].value ) {
                return items;
            }
            return $.map( items, function( item ) {
                if ( typeof item === "string" ) {
                    return {
                        label: item,
                        value: item
                    };
                }
                return $.extend( {}, item, {
                    label: item.label || item.value,
                    value: item.value || item.label
                });
            });
        },

        _suggest: function( items ) {
            var ul = this.menu.element.empty();
            this._rendermenu( ul, items );
            this.isnewmenu = true;
            this.menu.refresh();

            // size and position menu
            ul.show();
            this._resizemenu();
            ul.position( $.extend({
                of: this.element
            }, this.options.position ) );

            if ( this.options.autofocus ) {
                this.menu.next();
            }
        },

        _resizemenu: function() {
            var ul = this.menu.element;
            ul.outerwidth( math.max(
                // firefox wraps long text (possibly a rounding bug)
                // so we add 1px to avoid the wrapping (#7513)
                    ul.width( "" ).outerwidth() + 1,
                this.element.outerwidth()
            ) );
        },

        _rendermenu: function( ul, items ) {
            var that = this;
            $.each( items, function( index, item ) {
                that._renderitemdata( ul, item );
            });
        },

        _renderitemdata: function( ul, item ) {
            return this._renderitem( ul, item ).data( "ui-autocomplete-item", item );
        },

        _renderitem: function( ul, item ) {
            return $( "<li>" ).text( item.label ).appendto( ul );
        },

        _move: function( direction, event ) {
            if ( !this.menu.element.is( ":visible" ) ) {
                this.search( null, event );
                return;
            }
            if ( this.menu.isfirstitem() && /^previous/.test( direction ) ||
                this.menu.islastitem() && /^next/.test( direction ) ) {

                if ( !this.ismultiline ) {
                    this._value( this.term );
                }

                this.menu.blur();
                return;
            }
            this.menu[ direction ]( event );
        },

        widget: function() {
            return this.menu.element;
        },

        _value: function() {
            return this.valuemethod.apply( this.element, arguments );
        },

        _keyevent: function( keyevent, event ) {
            if ( !this.ismultiline || this.menu.element.is( ":visible" ) ) {
                this._move( keyevent, event );

                // prevents moving cursor to beginning/end of the text field in some browsers
                event.preventdefault();
            }
        }
    });

    $.extend( $.ui.autocomplete, {
        escaperegex: function( value ) {
            return value.replace( /[\-\[\]{}()*+?.,\\\^$|#\s]/g, "\\$&" );
        },
        filter: function( array, term ) {
            var matcher = new regexp( $.ui.autocomplete.escaperegex( term ), "i" );
            return $.grep( array, function( value ) {
                return matcher.test( value.label || value.value || value );
            });
        }
    });

// live region extension, adding a `messages` option
// note: this is an experimental api. we are still investigating
// a full solution for string manipulation and internationalization.
    $.widget( "ui.autocomplete", $.ui.autocomplete, {
        options: {
            messages: {
                noresults: "no search results.",
                results: function( amount ) {
                    return amount + ( amount > 1 ? " results are" : " result is" ) +
                        " available, use up and down arrow keys to navigate.";
                }
            }
        },

        __response: function( content ) {
            var message;
            this._superapply( arguments );
            if ( this.options.disabled || this.cancelsearch ) {
                return;
            }
            if ( content && content.length ) {
                message = this.options.messages.results( content.length );
            } else {
                message = this.options.messages.noresults;
            }
            this.liveregion.children().hide();
            $( "<div>" ).text( message ).appendto( this.liveregion );
        }
    });

    var autocomplete = $.ui.autocomplete;


    /*!
     * jquery ui button 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/button/
     */


    var lastactive,
        baseclasses = "ui-button ui-widget ui-state-default ui-corner-all",
        typeclasses = "ui-button-icons-only ui-button-icon-only ui-button-text-icons ui-button-text-icon-primary ui-button-text-icon-secondary ui-button-text-only",
        formresethandler = function() {
            var form = $( this );
            settimeout(function() {
                form.find( ":ui-button" ).button( "refresh" );
            }, 1 );
        },
        radiogroup = function( radio ) {
            var name = radio.name,
                form = radio.form,
                radios = $( [] );
            if ( name ) {
                name = name.replace( /'/g, "\\'" );
                if ( form ) {
                    radios = $( form ).find( "[name='" + name + "'][type=radio]" );
                } else {
                    radios = $( "[name='" + name + "'][type=radio]", radio.ownerdocument )
                        .filter(function() {
                            return !this.form;
                        });
                }
            }
            return radios;
        };

    $.widget( "ui.button", {
        version: "1.11.2",
        defaultelement: "<button>",
        options: {
            disabled: null,
            text: true,
            label: null,
            icons: {
                primary: null,
                secondary: null
            }
        },
        _create: function() {
            this.element.closest( "form" )
                .unbind( "reset" + this.eventnamespace )
                .bind( "reset" + this.eventnamespace, formresethandler );

            if ( typeof this.options.disabled !== "boolean" ) {
                this.options.disabled = !!this.element.prop( "disabled" );
            } else {
                this.element.prop( "disabled", this.options.disabled );
            }

            this._determinebuttontype();
            this.hastitle = !!this.buttonelement.attr( "title" );

            var that = this,
                options = this.options,
                togglebutton = this.type === "checkbox" || this.type === "radio",
                activeclass = !togglebutton ? "ui-state-active" : "";

            if ( options.label === null ) {
                options.label = (this.type === "input" ? this.buttonelement.val() : this.buttonelement.html());
            }

            this._hoverable( this.buttonelement );

            this.buttonelement
                .addclass( baseclasses )
                .attr( "role", "button" )
                .bind( "mouseenter" + this.eventnamespace, function() {
                    if ( options.disabled ) {
                        return;
                    }
                    if ( this === lastactive ) {
                        $( this ).addclass( "ui-state-active" );
                    }
                })
                .bind( "mouseleave" + this.eventnamespace, function() {
                    if ( options.disabled ) {
                        return;
                    }
                    $( this ).removeclass( activeclass );
                })
                .bind( "click" + this.eventnamespace, function( event ) {
                    if ( options.disabled ) {
                        event.preventdefault();
                        event.stopimmediatepropagation();
                    }
                });

            // can't use _focusable() because the element that receives focus
            // and the element that gets the ui-state-focus class are different
            this._on({
                focus: function() {
                    this.buttonelement.addclass( "ui-state-focus" );
                },
                blur: function() {
                    this.buttonelement.removeclass( "ui-state-focus" );
                }
            });

            if ( togglebutton ) {
                this.element.bind( "change" + this.eventnamespace, function() {
                    that.refresh();
                });
            }

            if ( this.type === "checkbox" ) {
                this.buttonelement.bind( "click" + this.eventnamespace, function() {
                    if ( options.disabled ) {
                        return false;
                    }
                });
            } else if ( this.type === "radio" ) {
                this.buttonelement.bind( "click" + this.eventnamespace, function() {
                    if ( options.disabled ) {
                        return false;
                    }
                    $( this ).addclass( "ui-state-active" );
                    that.buttonelement.attr( "aria-pressed", "true" );

                    var radio = that.element[ 0 ];
                    radiogroup( radio )
                        .not( radio )
                        .map(function() {
                            return $( this ).button( "widget" )[ 0 ];
                        })
                        .removeclass( "ui-state-active" )
                        .attr( "aria-pressed", "false" );
                });
            } else {
                this.buttonelement
                    .bind( "mousedown" + this.eventnamespace, function() {
                        if ( options.disabled ) {
                            return false;
                        }
                        $( this ).addclass( "ui-state-active" );
                        lastactive = this;
                        that.document.one( "mouseup", function() {
                            lastactive = null;
                        });
                    })
                    .bind( "mouseup" + this.eventnamespace, function() {
                        if ( options.disabled ) {
                            return false;
                        }
                        $( this ).removeclass( "ui-state-active" );
                    })
                    .bind( "keydown" + this.eventnamespace, function(event) {
                        if ( options.disabled ) {
                            return false;
                        }
                        if ( event.keycode === $.ui.keycode.space || event.keycode === $.ui.keycode.enter ) {
                            $( this ).addclass( "ui-state-active" );
                        }
                    })
                    // see #8559, we bind to blur here in case the button element loses
                    // focus between keydown and keyup, it would be left in an "active" state
                    .bind( "keyup" + this.eventnamespace + " blur" + this.eventnamespace, function() {
                        $( this ).removeclass( "ui-state-active" );
                    });

                if ( this.buttonelement.is("a") ) {
                    this.buttonelement.keyup(function(event) {
                        if ( event.keycode === $.ui.keycode.space ) {
                            // todo pass through original event correctly (just as 2nd argument doesn't work)
                            $( this ).click();
                        }
                    });
                }
            }

            this._setoption( "disabled", options.disabled );
            this._resetbutton();
        },

        _determinebuttontype: function() {
            var ancestor, labelselector, checked;

            if ( this.element.is("[type=checkbox]") ) {
                this.type = "checkbox";
            } else if ( this.element.is("[type=radio]") ) {
                this.type = "radio";
            } else if ( this.element.is("input") ) {
                this.type = "input";
            } else {
                this.type = "button";
            }

            if ( this.type === "checkbox" || this.type === "radio" ) {
                // we don't search against the document in case the element
                // is disconnected from the dom
                ancestor = this.element.parents().last();
                labelselector = "label[for='" + this.element.attr("id") + "']";
                this.buttonelement = ancestor.find( labelselector );
                if ( !this.buttonelement.length ) {
                    ancestor = ancestor.length ? ancestor.siblings() : this.element.siblings();
                    this.buttonelement = ancestor.filter( labelselector );
                    if ( !this.buttonelement.length ) {
                        this.buttonelement = ancestor.find( labelselector );
                    }
                }
                this.element.addclass( "ui-helper-hidden-accessible" );

                checked = this.element.is( ":checked" );
                if ( checked ) {
                    this.buttonelement.addclass( "ui-state-active" );
                }
                this.buttonelement.prop( "aria-pressed", checked );
            } else {
                this.buttonelement = this.element;
            }
        },

        widget: function() {
            return this.buttonelement;
        },

        _destroy: function() {
            this.element
                .removeclass( "ui-helper-hidden-accessible" );
            this.buttonelement
                .removeclass( baseclasses + " ui-state-active " + typeclasses )
                .removeattr( "role" )
                .removeattr( "aria-pressed" )
                .html( this.buttonelement.find(".ui-button-text").html() );

            if ( !this.hastitle ) {
                this.buttonelement.removeattr( "title" );
            }
        },

        _setoption: function( key, value ) {
            this._super( key, value );
            if ( key === "disabled" ) {
                this.widget().toggleclass( "ui-state-disabled", !!value );
                this.element.prop( "disabled", !!value );
                if ( value ) {
                    if ( this.type === "checkbox" || this.type === "radio" ) {
                        this.buttonelement.removeclass( "ui-state-focus" );
                    } else {
                        this.buttonelement.removeclass( "ui-state-focus ui-state-active" );
                    }
                }
                return;
            }
            this._resetbutton();
        },

        refresh: function() {
            //see #8237 & #8828
            var isdisabled = this.element.is( "input, button" ) ? this.element.is( ":disabled" ) : this.element.hasclass( "ui-button-disabled" );

            if ( isdisabled !== this.options.disabled ) {
                this._setoption( "disabled", isdisabled );
            }
            if ( this.type === "radio" ) {
                radiogroup( this.element[0] ).each(function() {
                    if ( $( this ).is( ":checked" ) ) {
                        $( this ).button( "widget" )
                            .addclass( "ui-state-active" )
                            .attr( "aria-pressed", "true" );
                    } else {
                        $( this ).button( "widget" )
                            .removeclass( "ui-state-active" )
                            .attr( "aria-pressed", "false" );
                    }
                });
            } else if ( this.type === "checkbox" ) {
                if ( this.element.is( ":checked" ) ) {
                    this.buttonelement
                        .addclass( "ui-state-active" )
                        .attr( "aria-pressed", "true" );
                } else {
                    this.buttonelement
                        .removeclass( "ui-state-active" )
                        .attr( "aria-pressed", "false" );
                }
            }
        },

        _resetbutton: function() {
            if ( this.type === "input" ) {
                if ( this.options.label ) {
                    this.element.val( this.options.label );
                }
                return;
            }
            var buttonelement = this.buttonelement.removeclass( typeclasses ),
                buttontext = $( "<span></span>", this.document[0] )
                    .addclass( "ui-button-text" )
                    .html( this.options.label )
                    .appendto( buttonelement.empty() )
                    .text(),
                icons = this.options.icons,
                multipleicons = icons.primary && icons.secondary,
                buttonclasses = [];

            if ( icons.primary || icons.secondary ) {
                if ( this.options.text ) {
                    buttonclasses.push( "ui-button-text-icon" + ( multipleicons ? "s" : ( icons.primary ? "-primary" : "-secondary" ) ) );
                }

                if ( icons.primary ) {
                    buttonelement.prepend( "<span class='ui-button-icon-primary ui-icon " + icons.primary + "'></span>" );
                }

                if ( icons.secondary ) {
                    buttonelement.append( "<span class='ui-button-icon-secondary ui-icon " + icons.secondary + "'></span>" );
                }

                if ( !this.options.text ) {
                    buttonclasses.push( multipleicons ? "ui-button-icons-only" : "ui-button-icon-only" );

                    if ( !this.hastitle ) {
                        buttonelement.attr( "title", $.trim( buttontext ) );
                    }
                }
            } else {
                buttonclasses.push( "ui-button-text-only" );
            }
            buttonelement.addclass( buttonclasses.join( " " ) );
        }
    });

    $.widget( "ui.buttonset", {
        version: "1.11.2",
        options: {
            items: "button, input[type=button], input[type=submit], input[type=reset], input[type=checkbox], input[type=radio], a, :data(ui-button)"
        },

        _create: function() {
            this.element.addclass( "ui-buttonset" );
        },

        _init: function() {
            this.refresh();
        },

        _setoption: function( key, value ) {
            if ( key === "disabled" ) {
                this.buttons.button( "option", key, value );
            }

            this._super( key, value );
        },

        refresh: function() {
            var rtl = this.element.css( "direction" ) === "rtl",
                allbuttons = this.element.find( this.options.items ),
                existingbuttons = allbuttons.filter( ":ui-button" );

            // initialize new buttons
            allbuttons.not( ":ui-button" ).button();

            // refresh existing buttons
            existingbuttons.button( "refresh" );

            this.buttons = allbuttons
                .map(function() {
                    return $( this ).button( "widget" )[ 0 ];
                })
                .removeclass( "ui-corner-all ui-corner-left ui-corner-right" )
                .filter( ":first" )
                .addclass( rtl ? "ui-corner-right" : "ui-corner-left" )
                .end()
                .filter( ":last" )
                .addclass( rtl ? "ui-corner-left" : "ui-corner-right" )
                .end()
                .end();
        },

        _destroy: function() {
            this.element.removeclass( "ui-buttonset" );
            this.buttons
                .map(function() {
                    return $( this ).button( "widget" )[ 0 ];
                })
                .removeclass( "ui-corner-left ui-corner-right" )
                .end()
                .button( "destroy" );
        }
    });

    var button = $.ui.button;


    /*!
     * jquery ui datepicker 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/datepicker/
     */


    $.extend($.ui, { datepicker: { version: "1.11.2" } });

    var datepicker_instactive;

    function datepicker_getzindex( elem ) {
        var position, value;
        while ( elem.length && elem[ 0 ] !== document ) {
            // ignore z-index if position is set to a value where z-index is ignored by the browser
            // this makes behavior of this function consistent across browsers
            // webkit always returns auto if the element is positioned
            position = elem.css( "position" );
            if ( position === "absolute" || position === "relative" || position === "fixed" ) {
                // ie returns 0 when zindex is not specified
                // other browsers return a string
                // we ignore the case of nested elements with an explicit value of 0
                // <div style="z-index: -10;"><div style="z-index: 0;"></div></div>
                value = parseint( elem.css( "zindex" ), 10 );
                if ( !isnan( value ) && value !== 0 ) {
                    return value;
                }
            }
            elem = elem.parent();
        }

        return 0;
    }
    /* date picker manager.
     use the singleton instance of this class, $.datepicker, to interact with the date picker.
     settings for (groups of) date pickers are maintained in an instance object,
     allowing multiple different settings on the same page. */

    function datepicker() {
        this._curinst = null; // the current instance in use
        this._keyevent = false; // if the last event was a key event
        this._disabledinputs = []; // list of date picker inputs that have been disabled
        this._datepickershowing = false; // true if the popup picker is showing , false if not
        this._indialog = false; // true if showing within a "dialog", false if not
        this._maindivid = "ui-datepicker-div"; // the id of the main datepicker division
        this._inlineclass = "ui-datepicker-inline"; // the name of the inline marker class
        this._appendclass = "ui-datepicker-append"; // the name of the append marker class
        this._triggerclass = "ui-datepicker-trigger"; // the name of the trigger marker class
        this._dialogclass = "ui-datepicker-dialog"; // the name of the dialog marker class
        this._disableclass = "ui-datepicker-disabled"; // the name of the disabled covering marker class
        this._unselectableclass = "ui-datepicker-unselectable"; // the name of the unselectable cell marker class
        this._currentclass = "ui-datepicker-current-day"; // the name of the current day marker class
        this._dayoverclass = "ui-datepicker-days-cell-over"; // the name of the day hover marker class
        this.regional = []; // available regional settings, indexed by language code
        this.regional[""] = { // default regional settings
            closetext: "done", // display text for close link
            prevtext: "prev", // display text for previous month link
            nexttext: "next", // display text for next month link
            currenttext: "today", // display text for current month link
            monthnames: ["january","february","march","april","may","june",
                "july","august","september","october","november","december"], // names of months for drop-down and formatting
            monthnamesshort: ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], // for formatting
            daynames: ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"], // for formatting
            daynamesshort: ["sun", "mon", "tue", "wed", "thu", "fri", "sat"], // for formatting
            daynamesmin: ["su","mo","tu","we","th","fr","sa"], // column headings for days starting at sunday
            weekheader: "wk", // column header for week of the year
            dateformat: "mm/dd/yy", // see format options on parsedate
            firstday: 0, // the first day of the week, sun = 0, mon = 1, ...
            isrtl: false, // true if right-to-left language, false if left-to-right
            showmonthafteryear: false, // true if the year select precedes month, false for month then year
            yearsuffix: "" // additional text to append to the year in the month headers
        };
        this._defaults = { // global defaults for all the date picker instances
            showon: "focus", // "focus" for popup on focus,
            // "button" for trigger button, or "both" for either
            showanim: "fadein", // name of jquery animation for popup
            showoptions: {}, // options for enhanced animations
            defaultdate: null, // used when field is blank: actual date,
            // +/-number for offset from today, null for today
            appendtext: "", // display text following the input box, e.g. showing the format
            buttontext: "...", // text for trigger button
            buttonimage: "", // url for trigger button image
            buttonimageonly: false, // true if the image appears alone, false if it appears on a button
            hideifnoprevnext: false, // true to hide next/previous month links
            // if not applicable, false to just disable them
            navigationasdateformat: false, // true if date formatting applied to prev/today/next links
            gotocurrent: false, // true if today link goes back to current selection instead
            changemonth: false, // true if month can be selected directly, false if only prev/next
            changeyear: false, // true if year can be selected directly, false if only prev/next
            yearrange: "c-10:c+10", // range of years to display in drop-down,
            // either relative to today's year (-nn:+nn), relative to currently displayed year
            // (c-nn:c+nn), absolute (nnnn:nnnn), or a combination of the above (nnnn:-n)
            showothermonths: false, // true to show dates in other months, false to leave blank
            selectothermonths: false, // true to allow selection of dates in other months, false for unselectable
            showweek: false, // true to show week of the year, false to not show it
            calculateweek: this.iso8601week, // how to calculate the week of the year,
            // takes a date and returns the number of the week for it
            shortyearcutoff: "+10", // short year values < this are in the current century,
            // > this are in the previous century,
            // string value starting with "+" for current year + value
            mindate: null, // the earliest selectable date, or null for no limit
            maxdate: null, // the latest selectable date, or null for no limit
            duration: "fast", // duration of display/closure
            beforeshowday: null, // function that takes a date and returns an array with
            // [0] = true if selectable, false if not, [1] = custom css class name(s) or "",
            // [2] = cell title (optional), e.g. $.datepicker.noweekends
            beforeshow: null, // function that takes an input field and
            // returns a set of custom settings for the date picker
            onselect: null, // define a callback function when a date is selected
            onchangemonthyear: null, // define a callback function when the month or year is changed
            onclose: null, // define a callback function when the datepicker is closed
            numberofmonths: 1, // number of months to show at a time
            showcurrentatpos: 0, // the position in multipe months at which to show the current month (starting at 0)
            stepmonths: 1, // number of months to step back/forward
            stepbigmonths: 12, // number of months to step back/forward for the big links
            altfield: "", // selector for an alternate field to store selected dates into
            altformat: "", // the date format to use for the alternate field
            constraininput: true, // the input is constrained by the current date format
            showbuttonpanel: false, // true to show button panel, false to not show it
            autosize: false, // true to size the input for the date format, false to leave as is
            disabled: false // the initial disabled state
        };
        $.extend(this._defaults, this.regional[""]);
        this.regional.en = $.extend( true, {}, this.regional[ "" ]);
        this.regional[ "en-us" ] = $.extend( true, {}, this.regional.en );
        this.dpdiv = datepicker_bindhover($("<div id='" + this._maindivid + "' class='ui-datepicker ui-widget ui-widget-content ui-helper-clearfix ui-corner-all'></div>"));
    }

    $.extend(datepicker.prototype, {
        /* class name added to elements to indicate already configured with a date picker. */
        markerclassname: "hasdatepicker",

        //keep track of the maximum number of rows displayed (see #7043)
        maxrows: 4,

        // todo rename to "widget" when switching to widget factory
        _widgetdatepicker: function() {
            return this.dpdiv;
        },

        /* override the default settings for all instances of the date picker.
         * @param  settings  object - the new settings to use as defaults (anonymous object)
         * @return the manager object
         */
        setdefaults: function(settings) {
            datepicker_extendremove(this._defaults, settings || {});
            return this;
        },

        /* attach the date picker to a jquery selection.
         * @param  target	element - the target input field or division or span
         * @param  settings  object - the new settings to use for this date picker instance (anonymous)
         */
        _attachdatepicker: function(target, settings) {
            var nodename, inline, inst;
            nodename = target.nodename.tolowercase();
            inline = (nodename === "div" || nodename === "span");
            if (!target.id) {
                this.uuid += 1;
                target.id = "dp" + this.uuid;
            }
            inst = this._newinst($(target), inline);
            inst.settings = $.extend({}, settings || {});
            if (nodename === "input") {
                this._connectdatepicker(target, inst);
            } else if (inline) {
                this._inlinedatepicker(target, inst);
            }
        },

        /* create a new instance object. */
        _newinst: function(target, inline) {
            var id = target[0].id.replace(/([^a-za-z0-9_\-])/g, "\\\\$1"); // escape jquery meta chars
            return {id: id, input: target, // associated target
                selectedday: 0, selectedmonth: 0, selectedyear: 0, // current selection
                drawmonth: 0, drawyear: 0, // month being drawn
                inline: inline, // is datepicker inline or not
                dpdiv: (!inline ? this.dpdiv : // presentation div
                    datepicker_bindhover($("<div class='" + this._inlineclass + " ui-datepicker ui-widget ui-widget-content ui-helper-clearfix ui-corner-all'></div>")))};
        },

        /* attach the date picker to an input field. */
        _connectdatepicker: function(target, inst) {
            var input = $(target);
            inst.append = $([]);
            inst.trigger = $([]);
            if (input.hasclass(this.markerclassname)) {
                return;
            }
            this._attachments(input, inst);
            input.addclass(this.markerclassname).keydown(this._dokeydown).
                keypress(this._dokeypress).keyup(this._dokeyup);
            this._autosize(inst);
            $.data(target, "datepicker", inst);
            //if disabled option is true, disable the datepicker once it has been attached to the input (see ticket #5665)
            if( inst.settings.disabled ) {
                this._disabledatepicker( target );
            }
        },

        /* make attachments based on settings. */
        _attachments: function(input, inst) {
            var showon, buttontext, buttonimage,
                appendtext = this._get(inst, "appendtext"),
                isrtl = this._get(inst, "isrtl");

            if (inst.append) {
                inst.append.remove();
            }
            if (appendtext) {
                inst.append = $("<span class='" + this._appendclass + "'>" + appendtext + "</span>");
                input[isrtl ? "before" : "after"](inst.append);
            }

            input.unbind("focus", this._showdatepicker);

            if (inst.trigger) {
                inst.trigger.remove();
            }

            showon = this._get(inst, "showon");
            if (showon === "focus" || showon === "both") { // pop-up date picker when in the marked field
                input.focus(this._showdatepicker);
            }
            if (showon === "button" || showon === "both") { // pop-up date picker when button clicked
                buttontext = this._get(inst, "buttontext");
                buttonimage = this._get(inst, "buttonimage");
                inst.trigger = $(this._get(inst, "buttonimageonly") ?
                    $("<img/>").addclass(this._triggerclass).
                        attr({ src: buttonimage, alt: buttontext, title: buttontext }) :
                    $("<button type='button'></button>").addclass(this._triggerclass).
                        html(!buttonimage ? buttontext : $("<img/>").attr(
                            { src:buttonimage, alt:buttontext, title:buttontext })));
                input[isrtl ? "before" : "after"](inst.trigger);
                inst.trigger.click(function() {
                    if ($.datepicker._datepickershowing && $.datepicker._lastinput === input[0]) {
                        $.datepicker._hidedatepicker();
                    } else if ($.datepicker._datepickershowing && $.datepicker._lastinput !== input[0]) {
                        $.datepicker._hidedatepicker();
                        $.datepicker._showdatepicker(input[0]);
                    } else {
                        $.datepicker._showdatepicker(input[0]);
                    }
                    return false;
                });
            }
        },

        /* apply the maximum length for the date format. */
        _autosize: function(inst) {
            if (this._get(inst, "autosize") && !inst.inline) {
                var findmax, max, maxi, i,
                    date = new date(2009, 12 - 1, 20), // ensure double digits
                    dateformat = this._get(inst, "dateformat");

                if (dateformat.match(/[dm]/)) {
                    findmax = function(names) {
                        max = 0;
                        maxi = 0;
                        for (i = 0; i < names.length; i++) {
                            if (names[i].length > max) {
                                max = names[i].length;
                                maxi = i;
                            }
                        }
                        return maxi;
                    };
                    date.setmonth(findmax(this._get(inst, (dateformat.match(/mm/) ?
                        "monthnames" : "monthnamesshort"))));
                    date.setdate(findmax(this._get(inst, (dateformat.match(/dd/) ?
                        "daynames" : "daynamesshort"))) + 20 - date.getday());
                }
                inst.input.attr("size", this._formatdate(inst, date).length);
            }
        },

        /* attach an inline date picker to a div. */
        _inlinedatepicker: function(target, inst) {
            var divspan = $(target);
            if (divspan.hasclass(this.markerclassname)) {
                return;
            }
            divspan.addclass(this.markerclassname).append(inst.dpdiv);
            $.data(target, "datepicker", inst);
            this._setdate(inst, this._getdefaultdate(inst), true);
            this._updatedatepicker(inst);
            this._updatealternate(inst);
            //if disabled option is true, disable the datepicker before showing it (see ticket #5665)
            if( inst.settings.disabled ) {
                this._disabledatepicker( target );
            }
            // set display:block in place of inst.dpdiv.show() which won't work on disconnected elements
            // http://bugs.jqueryui.com/ticket/7552 - a datepicker created on a detached div has zero height
            inst.dpdiv.css( "display", "block" );
        },

        /* pop-up the date picker in a "dialog" box.
         * @param  input element - ignored
         * @param  date	string or date - the initial date to display
         * @param  onselect  function - the function to call when a date is selected
         * @param  settings  object - update the dialog date picker instance's settings (anonymous object)
         * @param  pos int[2] - coordinates for the dialog's position within the screen or
         *					event - with x/y coordinates or
         *					leave empty for default (screen centre)
         * @return the manager object
         */
        _dialogdatepicker: function(input, date, onselect, settings, pos) {
            var id, browserwidth, browserheight, scrollx, scrolly,
                inst = this._dialoginst; // internal instance

            if (!inst) {
                this.uuid += 1;
                id = "dp" + this.uuid;
                this._dialoginput = $("<input type='text' id='" + id +
                    "' style='position: absolute; top: -100px; width: 0px;'/>");
                this._dialoginput.keydown(this._dokeydown);
                $("body").append(this._dialoginput);
                inst = this._dialoginst = this._newinst(this._dialoginput, false);
                inst.settings = {};
                $.data(this._dialoginput[0], "datepicker", inst);
            }
            datepicker_extendremove(inst.settings, settings || {});
            date = (date && date.constructor === date ? this._formatdate(inst, date) : date);
            this._dialoginput.val(date);

            this._pos = (pos ? (pos.length ? pos : [pos.pagex, pos.pagey]) : null);
            if (!this._pos) {
                browserwidth = document.documentelement.clientwidth;
                browserheight = document.documentelement.clientheight;
                scrollx = document.documentelement.scrollleft || document.body.scrollleft;
                scrolly = document.documentelement.scrolltop || document.body.scrolltop;
                this._pos = // should use actual width/height below
                    [(browserwidth / 2) - 100 + scrollx, (browserheight / 2) - 150 + scrolly];
            }

            // move input on screen for focus, but hidden behind dialog
            this._dialoginput.css("left", (this._pos[0] + 20) + "px").css("top", this._pos[1] + "px");
            inst.settings.onselect = onselect;
            this._indialog = true;
            this.dpdiv.addclass(this._dialogclass);
            this._showdatepicker(this._dialoginput[0]);
            if ($.blockui) {
                $.blockui(this.dpdiv);
            }
            $.data(this._dialoginput[0], "datepicker", inst);
            return this;
        },

        /* detach a datepicker from its control.
         * @param  target	element - the target input field or division or span
         */
        _destroydatepicker: function(target) {
            var nodename,
                $target = $(target),
                inst = $.data(target, "datepicker");

            if (!$target.hasclass(this.markerclassname)) {
                return;
            }

            nodename = target.nodename.tolowercase();
            $.removedata(target, "datepicker");
            if (nodename === "input") {
                inst.append.remove();
                inst.trigger.remove();
                $target.removeclass(this.markerclassname).
                    unbind("focus", this._showdatepicker).
                    unbind("keydown", this._dokeydown).
                    unbind("keypress", this._dokeypress).
                    unbind("keyup", this._dokeyup);
            } else if (nodename === "div" || nodename === "span") {
                $target.removeclass(this.markerclassname).empty();
            }
        },

        /* enable the date picker to a jquery selection.
         * @param  target	element - the target input field or division or span
         */
        _enabledatepicker: function(target) {
            var nodename, inline,
                $target = $(target),
                inst = $.data(target, "datepicker");

            if (!$target.hasclass(this.markerclassname)) {
                return;
            }

            nodename = target.nodename.tolowercase();
            if (nodename === "input") {
                target.disabled = false;
                inst.trigger.filter("button").
                    each(function() { this.disabled = false; }).end().
                    filter("img").css({opacity: "1.0", cursor: ""});
            } else if (nodename === "div" || nodename === "span") {
                inline = $target.children("." + this._inlineclass);
                inline.children().removeclass("ui-state-disabled");
                inline.find("select.ui-datepicker-month, select.ui-datepicker-year").
                    prop("disabled", false);
            }
            this._disabledinputs = $.map(this._disabledinputs,
                function(value) { return (value === target ? null : value); }); // delete entry
        },

        /* disable the date picker to a jquery selection.
         * @param  target	element - the target input field or division or span
         */
        _disabledatepicker: function(target) {
            var nodename, inline,
                $target = $(target),
                inst = $.data(target, "datepicker");

            if (!$target.hasclass(this.markerclassname)) {
                return;
            }

            nodename = target.nodename.tolowercase();
            if (nodename === "input") {
                target.disabled = true;
                inst.trigger.filter("button").
                    each(function() { this.disabled = true; }).end().
                    filter("img").css({opacity: "0.5", cursor: "default"});
            } else if (nodename === "div" || nodename === "span") {
                inline = $target.children("." + this._inlineclass);
                inline.children().addclass("ui-state-disabled");
                inline.find("select.ui-datepicker-month, select.ui-datepicker-year").
                    prop("disabled", true);
            }
            this._disabledinputs = $.map(this._disabledinputs,
                function(value) { return (value === target ? null : value); }); // delete entry
            this._disabledinputs[this._disabledinputs.length] = target;
        },

        /* is the first field in a jquery collection disabled as a datepicker?
         * @param  target	element - the target input field or division or span
         * @return boolean - true if disabled, false if enabled
         */
        _isdisableddatepicker: function(target) {
            if (!target) {
                return false;
            }
            for (var i = 0; i < this._disabledinputs.length; i++) {
                if (this._disabledinputs[i] === target) {
                    return true;
                }
            }
            return false;
        },

        /* retrieve the instance data for the target control.
         * @param  target  element - the target input field or division or span
         * @return  object - the associated instance data
         * @throws  error if a jquery problem getting data
         */
        _getinst: function(target) {
            try {
                return $.data(target, "datepicker");
            }
            catch (err) {
                throw "missing instance data for this datepicker";
            }
        },

        /* update or retrieve the settings for a date picker attached to an input field or division.
         * @param  target  element - the target input field or division or span
         * @param  name	object - the new settings to update or
         *				string - the name of the setting to change or retrieve,
         *				when retrieving also "all" for all instance settings or
         *				"defaults" for all global defaults
         * @param  value   any - the new value for the setting
         *				(omit if above is an object or to retrieve a value)
         */
        _optiondatepicker: function(target, name, value) {
            var settings, date, mindate, maxdate,
                inst = this._getinst(target);

            if (arguments.length === 2 && typeof name === "string") {
                return (name === "defaults" ? $.extend({}, $.datepicker._defaults) :
                    (inst ? (name === "all" ? $.extend({}, inst.settings) :
                        this._get(inst, name)) : null));
            }

            settings = name || {};
            if (typeof name === "string") {
                settings = {};
                settings[name] = value;
            }

            if (inst) {
                if (this._curinst === inst) {
                    this._hidedatepicker();
                }

                date = this._getdatedatepicker(target, true);
                mindate = this._getminmaxdate(inst, "min");
                maxdate = this._getminmaxdate(inst, "max");
                datepicker_extendremove(inst.settings, settings);
                // reformat the old mindate/maxdate values if dateformat changes and a new mindate/maxdate isn't provided
                if (mindate !== null && settings.dateformat !== undefined && settings.mindate === undefined) {
                    inst.settings.mindate = this._formatdate(inst, mindate);
                }
                if (maxdate !== null && settings.dateformat !== undefined && settings.maxdate === undefined) {
                    inst.settings.maxdate = this._formatdate(inst, maxdate);
                }
                if ( "disabled" in settings ) {
                    if ( settings.disabled ) {
                        this._disabledatepicker(target);
                    } else {
                        this._enabledatepicker(target);
                    }
                }
                this._attachments($(target), inst);
                this._autosize(inst);
                this._setdate(inst, date);
                this._updatealternate(inst);
                this._updatedatepicker(inst);
            }
        },

        // change method deprecated
        _changedatepicker: function(target, name, value) {
            this._optiondatepicker(target, name, value);
        },

        /* redraw the date picker attached to an input field or division.
         * @param  target  element - the target input field or division or span
         */
        _refreshdatepicker: function(target) {
            var inst = this._getinst(target);
            if (inst) {
                this._updatedatepicker(inst);
            }
        },

        /* set the dates for a jquery selection.
         * @param  target element - the target input field or division or span
         * @param  date	date - the new date
         */
        _setdatedatepicker: function(target, date) {
            var inst = this._getinst(target);
            if (inst) {
                this._setdate(inst, date);
                this._updatedatepicker(inst);
                this._updatealternate(inst);
            }
        },

        /* get the date(s) for the first entry in a jquery selection.
         * @param  target element - the target input field or division or span
         * @param  nodefault boolean - true if no default date is to be used
         * @return date - the current date
         */
        _getdatedatepicker: function(target, nodefault) {
            var inst = this._getinst(target);
            if (inst && !inst.inline) {
                this._setdatefromfield(inst, nodefault);
            }
            return (inst ? this._getdate(inst) : null);
        },

        /* handle keystrokes. */
        _dokeydown: function(event) {
            var onselect, datestr, sel,
                inst = $.datepicker._getinst(event.target),
                handled = true,
                isrtl = inst.dpdiv.is(".ui-datepicker-rtl");

            inst._keyevent = true;
            if ($.datepicker._datepickershowing) {
                switch (event.keycode) {
                    case 9: $.datepicker._hidedatepicker();
                        handled = false;
                        break; // hide on tab out
                    case 13: sel = $("td." + $.datepicker._dayoverclass + ":not(." +
                        $.datepicker._currentclass + ")", inst.dpdiv);
                        if (sel[0]) {
                            $.datepicker._selectday(event.target, inst.selectedmonth, inst.selectedyear, sel[0]);
                        }

                        onselect = $.datepicker._get(inst, "onselect");
                        if (onselect) {
                            datestr = $.datepicker._formatdate(inst);

                            // trigger custom callback
                            onselect.apply((inst.input ? inst.input[0] : null), [datestr, inst]);
                        } else {
                            $.datepicker._hidedatepicker();
                        }

                        return false; // don't submit the form
                    case 27: $.datepicker._hidedatepicker();
                        break; // hide on escape
                    case 33: $.datepicker._adjustdate(event.target, (event.ctrlkey ?
                        -$.datepicker._get(inst, "stepbigmonths") :
                        -$.datepicker._get(inst, "stepmonths")), "m");
                        break; // previous month/year on page up/+ ctrl
                    case 34: $.datepicker._adjustdate(event.target, (event.ctrlkey ?
                        +$.datepicker._get(inst, "stepbigmonths") :
                        +$.datepicker._get(inst, "stepmonths")), "m");
                        break; // next month/year on page down/+ ctrl
                    case 35: if (event.ctrlkey || event.metakey) {
                        $.datepicker._cleardate(event.target);
                    }
                        handled = event.ctrlkey || event.metakey;
                        break; // clear on ctrl or command +end
                    case 36: if (event.ctrlkey || event.metakey) {
                        $.datepicker._gototoday(event.target);
                    }
                        handled = event.ctrlkey || event.metakey;
                        break; // current on ctrl or command +home
                    case 37: if (event.ctrlkey || event.metakey) {
                        $.datepicker._adjustdate(event.target, (isrtl ? +1 : -1), "d");
                    }
                        handled = event.ctrlkey || event.metakey;
                        // -1 day on ctrl or command +left
                        if (event.originalevent.altkey) {
                            $.datepicker._adjustdate(event.target, (event.ctrlkey ?
                                -$.datepicker._get(inst, "stepbigmonths") :
                                -$.datepicker._get(inst, "stepmonths")), "m");
                        }
                        // next month/year on alt +left on mac
                        break;
                    case 38: if (event.ctrlkey || event.metakey) {
                        $.datepicker._adjustdate(event.target, -7, "d");
                    }
                        handled = event.ctrlkey || event.metakey;
                        break; // -1 week on ctrl or command +up
                    case 39: if (event.ctrlkey || event.metakey) {
                        $.datepicker._adjustdate(event.target, (isrtl ? -1 : +1), "d");
                    }
                        handled = event.ctrlkey || event.metakey;
                        // +1 day on ctrl or command +right
                        if (event.originalevent.altkey) {
                            $.datepicker._adjustdate(event.target, (event.ctrlkey ?
                                +$.datepicker._get(inst, "stepbigmonths") :
                                +$.datepicker._get(inst, "stepmonths")), "m");
                        }
                        // next month/year on alt +right
                        break;
                    case 40: if (event.ctrlkey || event.metakey) {
                        $.datepicker._adjustdate(event.target, +7, "d");
                    }
                        handled = event.ctrlkey || event.metakey;
                        break; // +1 week on ctrl or command +down
                    default: handled = false;
                }
            } else if (event.keycode === 36 && event.ctrlkey) { // display the date picker on ctrl+home
                $.datepicker._showdatepicker(this);
            } else {
                handled = false;
            }

            if (handled) {
                event.preventdefault();
                event.stoppropagation();
            }
        },

        /* filter entered characters - based on date format. */
        _dokeypress: function(event) {
            var chars, chr,
                inst = $.datepicker._getinst(event.target);

            if ($.datepicker._get(inst, "constraininput")) {
                chars = $.datepicker._possiblechars($.datepicker._get(inst, "dateformat"));
                chr = string.fromcharcode(event.charcode == null ? event.keycode : event.charcode);
                return event.ctrlkey || event.metakey || (chr < " " || !chars || chars.indexof(chr) > -1);
            }
        },

        /* synchronise manual entry and field/alternate field. */
        _dokeyup: function(event) {
            var date,
                inst = $.datepicker._getinst(event.target);

            if (inst.input.val() !== inst.lastval) {
                try {
                    date = $.datepicker.parsedate($.datepicker._get(inst, "dateformat"),
                        (inst.input ? inst.input.val() : null),
                        $.datepicker._getformatconfig(inst));

                    if (date) { // only if valid
                        $.datepicker._setdatefromfield(inst);
                        $.datepicker._updatealternate(inst);
                        $.datepicker._updatedatepicker(inst);
                    }
                }
                catch (err) {
                }
            }
            return true;
        },

        /* pop-up the date picker for a given input field.
         * if false returned from beforeshow event handler do not show.
         * @param  input  element - the input field attached to the date picker or
         *					event - if triggered by focus
         */
        _showdatepicker: function(input) {
            input = input.target || input;
            if (input.nodename.tolowercase() !== "input") { // find from button/image trigger
                input = $("input", input.parentnode)[0];
            }

            if ($.datepicker._isdisableddatepicker(input) || $.datepicker._lastinput === input) { // already here
                return;
            }

            var inst, beforeshow, beforeshowsettings, isfixed,
                offset, showanim, duration;

            inst = $.datepicker._getinst(input);
            if ($.datepicker._curinst && $.datepicker._curinst !== inst) {
                $.datepicker._curinst.dpdiv.stop(true, true);
                if ( inst && $.datepicker._datepickershowing ) {
                    $.datepicker._hidedatepicker( $.datepicker._curinst.input[0] );
                }
            }

            beforeshow = $.datepicker._get(inst, "beforeshow");
            beforeshowsettings = beforeshow ? beforeshow.apply(input, [input, inst]) : {};
            if(beforeshowsettings === false){
                return;
            }
            datepicker_extendremove(inst.settings, beforeshowsettings);

            inst.lastval = null;
            $.datepicker._lastinput = input;
            $.datepicker._setdatefromfield(inst);

            if ($.datepicker._indialog) { // hide cursor
                input.value = "";
            }
            if (!$.datepicker._pos) { // position below input
                $.datepicker._pos = $.datepicker._findpos(input);
                $.datepicker._pos[1] += input.offsetheight; // add the height
            }

            isfixed = false;
            $(input).parents().each(function() {
                isfixed |= $(this).css("position") === "fixed";
                return !isfixed;
            });

            offset = {left: $.datepicker._pos[0], top: $.datepicker._pos[1]};
            $.datepicker._pos = null;
            //to avoid flashes on firefox
            inst.dpdiv.empty();
            // determine sizing offscreen
            inst.dpdiv.css({position: "absolute", display: "block", top: "-1000px"});
            $.datepicker._updatedatepicker(inst);
            // fix width for dynamic number of date pickers
            // and adjust position before showing
            offset = $.datepicker._checkoffset(inst, offset, isfixed);
            inst.dpdiv.css({position: ($.datepicker._indialog && $.blockui ?
                "static" : (isfixed ? "fixed" : "absolute")), display: "none",
                left: offset.left + "px", top: offset.top + "px"});

            if (!inst.inline) {
                showanim = $.datepicker._get(inst, "showanim");
                duration = $.datepicker._get(inst, "duration");
                inst.dpdiv.css( "z-index", datepicker_getzindex( $( input ) ) + 1 );
                $.datepicker._datepickershowing = true;

                if ( $.effects && $.effects.effect[ showanim ] ) {
                    inst.dpdiv.show(showanim, $.datepicker._get(inst, "showoptions"), duration);
                } else {
                    inst.dpdiv[showanim || "show"](showanim ? duration : null);
                }

                if ( $.datepicker._shouldfocusinput( inst ) ) {
                    inst.input.focus();
                }

                $.datepicker._curinst = inst;
            }
        },

        /* generate the date picker content. */
        _updatedatepicker: function(inst) {
            this.maxrows = 4; //reset the max number of rows being displayed (see #7043)
            datepicker_instactive = inst; // for delegate hover events
            inst.dpdiv.empty().append(this._generatehtml(inst));
            this._attachhandlers(inst);

            var origyearshtml,
                nummonths = this._getnumberofmonths(inst),
                cols = nummonths[1],
                width = 17,
                activecell = inst.dpdiv.find( "." + this._dayoverclass + " a" );

            if ( activecell.length > 0 ) {
                datepicker_handlemouseover.apply( activecell.get( 0 ) );
            }

            inst.dpdiv.removeclass("ui-datepicker-multi-2 ui-datepicker-multi-3 ui-datepicker-multi-4").width("");
            if (cols > 1) {
                inst.dpdiv.addclass("ui-datepicker-multi-" + cols).css("width", (width * cols) + "em");
            }
            inst.dpdiv[(nummonths[0] !== 1 || nummonths[1] !== 1 ? "add" : "remove") +
                "class"]("ui-datepicker-multi");
            inst.dpdiv[(this._get(inst, "isrtl") ? "add" : "remove") +
                "class"]("ui-datepicker-rtl");

            if (inst === $.datepicker._curinst && $.datepicker._datepickershowing && $.datepicker._shouldfocusinput( inst ) ) {
                inst.input.focus();
            }

            // deffered render of the years select (to avoid flashes on firefox)
            if( inst.yearshtml ){
                origyearshtml = inst.yearshtml;
                settimeout(function(){
                    //assure that inst.yearshtml didn't change.
                    if( origyearshtml === inst.yearshtml && inst.yearshtml ){
                        inst.dpdiv.find("select.ui-datepicker-year:first").replacewith(inst.yearshtml);
                    }
                    origyearshtml = inst.yearshtml = null;
                }, 0);
            }
        },

        // #6694 - don't focus the input if it's already focused
        // this breaks the change event in ie
        // support: ie and jquery <1.9
        _shouldfocusinput: function( inst ) {
            return inst.input && inst.input.is( ":visible" ) && !inst.input.is( ":disabled" ) && !inst.input.is( ":focus" );
        },

        /* check positioning to remain on screen. */
        _checkoffset: function(inst, offset, isfixed) {
            var dpwidth = inst.dpdiv.outerwidth(),
                dpheight = inst.dpdiv.outerheight(),
                inputwidth = inst.input ? inst.input.outerwidth() : 0,
                inputheight = inst.input ? inst.input.outerheight() : 0,
                viewwidth = document.documentelement.clientwidth + (isfixed ? 0 : $(document).scrollleft()),
                viewheight = document.documentelement.clientheight + (isfixed ? 0 : $(document).scrolltop());

            offset.left -= (this._get(inst, "isrtl") ? (dpwidth - inputwidth) : 0);
            offset.left -= (isfixed && offset.left === inst.input.offset().left) ? $(document).scrollleft() : 0;
            offset.top -= (isfixed && offset.top === (inst.input.offset().top + inputheight)) ? $(document).scrolltop() : 0;

            // now check if datepicker is showing outside window viewport - move to a better place if so.
            offset.left -= math.min(offset.left, (offset.left + dpwidth > viewwidth && viewwidth > dpwidth) ?
                math.abs(offset.left + dpwidth - viewwidth) : 0);
            offset.top -= math.min(offset.top, (offset.top + dpheight > viewheight && viewheight > dpheight) ?
                math.abs(dpheight + inputheight) : 0);

            return offset;
        },

        /* find an object's position on the screen. */
        _findpos: function(obj) {
            var position,
                inst = this._getinst(obj),
                isrtl = this._get(inst, "isrtl");

            while (obj && (obj.type === "hidden" || obj.nodetype !== 1 || $.expr.filters.hidden(obj))) {
                obj = obj[isrtl ? "previoussibling" : "nextsibling"];
            }

            position = $(obj).offset();
            return [position.left, position.top];
        },

        /* hide the date picker from view.
         * @param  input  element - the input field attached to the date picker
         */
        _hidedatepicker: function(input) {
            var showanim, duration, postprocess, onclose,
                inst = this._curinst;

            if (!inst || (input && inst !== $.data(input, "datepicker"))) {
                return;
            }

            if (this._datepickershowing) {
                showanim = this._get(inst, "showanim");
                duration = this._get(inst, "duration");
                postprocess = function() {
                    $.datepicker._tidydialog(inst);
                };

                // deprecated: after bc for 1.8.x $.effects[ showanim ] is not needed
                if ( $.effects && ( $.effects.effect[ showanim ] || $.effects[ showanim ] ) ) {
                    inst.dpdiv.hide(showanim, $.datepicker._get(inst, "showoptions"), duration, postprocess);
                } else {
                    inst.dpdiv[(showanim === "slidedown" ? "slideup" :
                        (showanim === "fadein" ? "fadeout" : "hide"))]((showanim ? duration : null), postprocess);
                }

                if (!showanim) {
                    postprocess();
                }
                this._datepickershowing = false;

                onclose = this._get(inst, "onclose");
                if (onclose) {
                    onclose.apply((inst.input ? inst.input[0] : null), [(inst.input ? inst.input.val() : ""), inst]);
                }

                this._lastinput = null;
                if (this._indialog) {
                    this._dialoginput.css({ position: "absolute", left: "0", top: "-100px" });
                    if ($.blockui) {
                        $.unblockui();
                        $("body").append(this.dpdiv);
                    }
                }
                this._indialog = false;
            }
        },

        /* tidy up after a dialog display. */
        _tidydialog: function(inst) {
            inst.dpdiv.removeclass(this._dialogclass).unbind(".ui-datepicker-calendar");
        },

        /* close date picker if clicked elsewhere. */
        _checkexternalclick: function(event) {
            if (!$.datepicker._curinst) {
                return;
            }

            var $target = $(event.target),
                inst = $.datepicker._getinst($target[0]);

            if ( ( ( $target[0].id !== $.datepicker._maindivid &&
                $target.parents("#" + $.datepicker._maindivid).length === 0 &&
                !$target.hasclass($.datepicker.markerclassname) &&
                !$target.closest("." + $.datepicker._triggerclass).length &&
                $.datepicker._datepickershowing && !($.datepicker._indialog && $.blockui) ) ) ||
                ( $target.hasclass($.datepicker.markerclassname) && $.datepicker._curinst !== inst ) ) {
                $.datepicker._hidedatepicker();
            }
        },

        /* adjust one of the date sub-fields. */
        _adjustdate: function(id, offset, period) {
            var target = $(id),
                inst = this._getinst(target[0]);

            if (this._isdisableddatepicker(target[0])) {
                return;
            }
            this._adjustinstdate(inst, offset +
                    (period === "m" ? this._get(inst, "showcurrentatpos") : 0), // undo positioning
                period);
            this._updatedatepicker(inst);
        },

        /* action for current link. */
        _gototoday: function(id) {
            var date,
                target = $(id),
                inst = this._getinst(target[0]);

            if (this._get(inst, "gotocurrent") && inst.currentday) {
                inst.selectedday = inst.currentday;
                inst.drawmonth = inst.selectedmonth = inst.currentmonth;
                inst.drawyear = inst.selectedyear = inst.currentyear;
            } else {
                date = new date();
                inst.selectedday = date.getdate();
                inst.drawmonth = inst.selectedmonth = date.getmonth();
                inst.drawyear = inst.selectedyear = date.getfullyear();
            }
            this._notifychange(inst);
            this._adjustdate(target);
        },

        /* action for selecting a new month/year. */
        _selectmonthyear: function(id, select, period) {
            var target = $(id),
                inst = this._getinst(target[0]);

            inst["selected" + (period === "m" ? "month" : "year")] =
                inst["draw" + (period === "m" ? "month" : "year")] =
                    parseint(select.options[select.selectedindex].value,10);

            this._notifychange(inst);
            this._adjustdate(target);
        },

        /* action for selecting a day. */
        _selectday: function(id, month, year, td) {
            var inst,
                target = $(id);

            if ($(td).hasclass(this._unselectableclass) || this._isdisableddatepicker(target[0])) {
                return;
            }

            inst = this._getinst(target[0]);
            inst.selectedday = inst.currentday = $("a", td).html();
            inst.selectedmonth = inst.currentmonth = month;
            inst.selectedyear = inst.currentyear = year;
            this._selectdate(id, this._formatdate(inst,
                inst.currentday, inst.currentmonth, inst.currentyear));
        },

        /* erase the input field and hide the date picker. */
        _cleardate: function(id) {
            var target = $(id);
            this._selectdate(target, "");
        },

        /* update the input field with the selected date. */
        _selectdate: function(id, datestr) {
            var onselect,
                target = $(id),
                inst = this._getinst(target[0]);

            datestr = (datestr != null ? datestr : this._formatdate(inst));
            if (inst.input) {
                inst.input.val(datestr);
            }
            this._updatealternate(inst);

            onselect = this._get(inst, "onselect");
            if (onselect) {
                onselect.apply((inst.input ? inst.input[0] : null), [datestr, inst]);  // trigger custom callback
            } else if (inst.input) {
                inst.input.trigger("change"); // fire the change event
            }

            if (inst.inline){
                this._updatedatepicker(inst);
            } else {
                this._hidedatepicker();
                this._lastinput = inst.input[0];
                if (typeof(inst.input[0]) !== "object") {
                    inst.input.focus(); // restore focus
                }
                this._lastinput = null;
            }
        },

        /* update any alternate field to synchronise with the main field. */
        _updatealternate: function(inst) {
            var altformat, date, datestr,
                altfield = this._get(inst, "altfield");

            if (altfield) { // update alternate field too
                altformat = this._get(inst, "altformat") || this._get(inst, "dateformat");
                date = this._getdate(inst);
                datestr = this.formatdate(altformat, date, this._getformatconfig(inst));
                $(altfield).each(function() { $(this).val(datestr); });
            }
        },

        /* set as beforeshowday function to prevent selection of weekends.
         * @param  date  date - the date to customise
         * @return [boolean, string] - is this date selectable?, what is its css class?
         */
        noweekends: function(date) {
            var day = date.getday();
            return [(day > 0 && day < 6), ""];
        },

        /* set as calculateweek to determine the week of the year based on the iso 8601 definition.
         * @param  date  date - the date to get the week for
         * @return  number - the number of the week within the year that contains this date
         */
        iso8601week: function(date) {
            var time,
                checkdate = new date(date.gettime());

            // find thursday of this week starting on monday
            checkdate.setdate(checkdate.getdate() + 4 - (checkdate.getday() || 7));

            time = checkdate.gettime();
            checkdate.setmonth(0); // compare with jan 1
            checkdate.setdate(1);
            return math.floor(math.round((time - checkdate) / 86400000) / 7) + 1;
        },

        /* parse a string value into a date object.
         * see formatdate below for the possible formats.
         *
         * @param  format string - the expected format of the date
         * @param  value string - the date in the above format
         * @param  settings object - attributes include:
         *					shortyearcutoff  number - the cutoff year for determining the century (optional)
         *					daynamesshort	string[7] - abbreviated names of the days from sunday (optional)
         *					daynames		string[7] - names of the days from sunday (optional)
         *					monthnamesshort string[12] - abbreviated names of the months (optional)
         *					monthnames		string[12] - names of the months (optional)
         * @return  date - the extracted date value or null if value is blank
         */
        parsedate: function (format, value, settings) {
            if (format == null || value == null) {
                throw "invalid arguments";
            }

            value = (typeof value === "object" ? value.tostring() : value + "");
            if (value === "") {
                return null;
            }

            var iformat, dim, extra,
                ivalue = 0,
                shortyearcutofftemp = (settings ? settings.shortyearcutoff : null) || this._defaults.shortyearcutoff,
                shortyearcutoff = (typeof shortyearcutofftemp !== "string" ? shortyearcutofftemp :
                    new date().getfullyear() % 100 + parseint(shortyearcutofftemp, 10)),
                daynamesshort = (settings ? settings.daynamesshort : null) || this._defaults.daynamesshort,
                daynames = (settings ? settings.daynames : null) || this._defaults.daynames,
                monthnamesshort = (settings ? settings.monthnamesshort : null) || this._defaults.monthnamesshort,
                monthnames = (settings ? settings.monthnames : null) || this._defaults.monthnames,
                year = -1,
                month = -1,
                day = -1,
                doy = -1,
                literal = false,
                date,
            // check whether a format character is doubled
                lookahead = function(match) {
                    var matches = (iformat + 1 < format.length && format.charat(iformat + 1) === match);
                    if (matches) {
                        iformat++;
                    }
                    return matches;
                },
            // extract a number from the string value
                getnumber = function(match) {
                    var isdoubled = lookahead(match),
                        size = (match === "@" ? 14 : (match === "!" ? 20 :
                            (match === "y" && isdoubled ? 4 : (match === "o" ? 3 : 2)))),
                        minsize = (match === "y" ? size : 1),
                        digits = new regexp("^\\d{" + minsize + "," + size + "}"),
                        num = value.substring(ivalue).match(digits);
                    if (!num) {
                        throw "missing number at position " + ivalue;
                    }
                    ivalue += num[0].length;
                    return parseint(num[0], 10);
                },
            // extract a name from the string value and convert to an index
                getname = function(match, shortnames, longnames) {
                    var index = -1,
                        names = $.map(lookahead(match) ? longnames : shortnames, function (v, k) {
                            return [ [k, v] ];
                        }).sort(function (a, b) {
                            return -(a[1].length - b[1].length);
                        });

                    $.each(names, function (i, pair) {
                        var name = pair[1];
                        if (value.substr(ivalue, name.length).tolowercase() === name.tolowercase()) {
                            index = pair[0];
                            ivalue += name.length;
                            return false;
                        }
                    });
                    if (index !== -1) {
                        return index + 1;
                    } else {
                        throw "unknown name at position " + ivalue;
                    }
                },
            // confirm that a literal character matches the string value
                checkliteral = function() {
                    if (value.charat(ivalue) !== format.charat(iformat)) {
                        throw "unexpected literal at position " + ivalue;
                    }
                    ivalue++;
                };

            for (iformat = 0; iformat < format.length; iformat++) {
                if (literal) {
                    if (format.charat(iformat) === "'" && !lookahead("'")) {
                        literal = false;
                    } else {
                        checkliteral();
                    }
                } else {
                    switch (format.charat(iformat)) {
                        case "d":
                            day = getnumber("d");
                            break;
                        case "d":
                            getname("d", daynamesshort, daynames);
                            break;
                        case "o":
                            doy = getnumber("o");
                            break;
                        case "m":
                            month = getnumber("m");
                            break;
                        case "m":
                            month = getname("m", monthnamesshort, monthnames);
                            break;
                        case "y":
                            year = getnumber("y");
                            break;
                        case "@":
                            date = new date(getnumber("@"));
                            year = date.getfullyear();
                            month = date.getmonth() + 1;
                            day = date.getdate();
                            break;
                        case "!":
                            date = new date((getnumber("!") - this._ticksto1970) / 10000);
                            year = date.getfullyear();
                            month = date.getmonth() + 1;
                            day = date.getdate();
                            break;
                        case "'":
                            if (lookahead("'")){
                                checkliteral();
                            } else {
                                literal = true;
                            }
                            break;
                        default:
                            checkliteral();
                    }
                }
            }

            if (ivalue < value.length){
                extra = value.substr(ivalue);
                if (!/^\s+/.test(extra)) {
                    throw "extra/unparsed characters found in date: " + extra;
                }
            }

            if (year === -1) {
                year = new date().getfullyear();
            } else if (year < 100) {
                year += new date().getfullyear() - new date().getfullyear() % 100 +
                    (year <= shortyearcutoff ? 0 : -100);
            }

            if (doy > -1) {
                month = 1;
                day = doy;
                do {
                    dim = this._getdaysinmonth(year, month - 1);
                    if (day <= dim) {
                        break;
                    }
                    month++;
                    day -= dim;
                } while (true);
            }

            date = this._daylightsavingadjust(new date(year, month - 1, day));
            if (date.getfullyear() !== year || date.getmonth() + 1 !== month || date.getdate() !== day) {
                throw "invalid date"; // e.g. 31/02/00
            }
            return date;
        },

        /* standard date formats. */
        atom: "yy-mm-dd", // rfc 3339 (iso 8601)
        cookie: "d, dd m yy",
        iso_8601: "yy-mm-dd",
        rfc_822: "d, d m y",
        rfc_850: "dd, dd-m-y",
        rfc_1036: "d, d m y",
        rfc_1123: "d, d m yy",
        rfc_2822: "d, d m yy",
        rss: "d, d m y", // rfc 822
        ticks: "!",
        timestamp: "@",
        w3c: "yy-mm-dd", // iso 8601

        _ticksto1970: (((1970 - 1) * 365 + math.floor(1970 / 4) - math.floor(1970 / 100) +
            math.floor(1970 / 400)) * 24 * 60 * 60 * 10000000),

        /* format a date object into a string value.
         * the format can be combinations of the following:
         * d  - day of month (no leading zero)
         * dd - day of month (two digit)
         * o  - day of year (no leading zeros)
         * oo - day of year (three digit)
         * d  - day name short
         * dd - day name long
         * m  - month of year (no leading zero)
         * mm - month of year (two digit)
         * m  - month name short
         * mm - month name long
         * y  - year (two digit)
         * yy - year (four digit)
         * @ - unix timestamp (ms since 01/01/1970)
         * ! - windows ticks (100ns since 01/01/0001)
         * "..." - literal text
         * '' - single quote
         *
         * @param  format string - the desired format of the date
         * @param  date date - the date value to format
         * @param  settings object - attributes include:
         *					daynamesshort	string[7] - abbreviated names of the days from sunday (optional)
         *					daynames		string[7] - names of the days from sunday (optional)
         *					monthnamesshort string[12] - abbreviated names of the months (optional)
         *					monthnames		string[12] - names of the months (optional)
         * @return  string - the date in the above format
         */
        formatdate: function (format, date, settings) {
            if (!date) {
                return "";
            }

            var iformat,
                daynamesshort = (settings ? settings.daynamesshort : null) || this._defaults.daynamesshort,
                daynames = (settings ? settings.daynames : null) || this._defaults.daynames,
                monthnamesshort = (settings ? settings.monthnamesshort : null) || this._defaults.monthnamesshort,
                monthnames = (settings ? settings.monthnames : null) || this._defaults.monthnames,
            // check whether a format character is doubled
                lookahead = function(match) {
                    var matches = (iformat + 1 < format.length && format.charat(iformat + 1) === match);
                    if (matches) {
                        iformat++;
                    }
                    return matches;
                },
            // format a number, with leading zero if necessary
                formatnumber = function(match, value, len) {
                    var num = "" + value;
                    if (lookahead(match)) {
                        while (num.length < len) {
                            num = "0" + num;
                        }
                    }
                    return num;
                },
            // format a name, short or long as requested
                formatname = function(match, value, shortnames, longnames) {
                    return (lookahead(match) ? longnames[value] : shortnames[value]);
                },
                output = "",
                literal = false;

            if (date) {
                for (iformat = 0; iformat < format.length; iformat++) {
                    if (literal) {
                        if (format.charat(iformat) === "'" && !lookahead("'")) {
                            literal = false;
                        } else {
                            output += format.charat(iformat);
                        }
                    } else {
                        switch (format.charat(iformat)) {
                            case "d":
                                output += formatnumber("d", date.getdate(), 2);
                                break;
                            case "d":
                                output += formatname("d", date.getday(), daynamesshort, daynames);
                                break;
                            case "o":
                                output += formatnumber("o",
                                    math.round((new date(date.getfullyear(), date.getmonth(), date.getdate()).gettime() - new date(date.getfullyear(), 0, 0).gettime()) / 86400000), 3);
                                break;
                            case "m":
                                output += formatnumber("m", date.getmonth() + 1, 2);
                                break;
                            case "m":
                                output += formatname("m", date.getmonth(), monthnamesshort, monthnames);
                                break;
                            case "y":
                                output += (lookahead("y") ? date.getfullyear() :
                                    (date.getyear() % 100 < 10 ? "0" : "") + date.getyear() % 100);
                                break;
                            case "@":
                                output += date.gettime();
                                break;
                            case "!":
                                output += date.gettime() * 10000 + this._ticksto1970;
                                break;
                            case "'":
                                if (lookahead("'")) {
                                    output += "'";
                                } else {
                                    literal = true;
                                }
                                break;
                            default:
                                output += format.charat(iformat);
                        }
                    }
                }
            }
            return output;
        },

        /* extract all possible characters from the date format. */
        _possiblechars: function (format) {
            var iformat,
                chars = "",
                literal = false,
            // check whether a format character is doubled
                lookahead = function(match) {
                    var matches = (iformat + 1 < format.length && format.charat(iformat + 1) === match);
                    if (matches) {
                        iformat++;
                    }
                    return matches;
                };

            for (iformat = 0; iformat < format.length; iformat++) {
                if (literal) {
                    if (format.charat(iformat) === "'" && !lookahead("'")) {
                        literal = false;
                    } else {
                        chars += format.charat(iformat);
                    }
                } else {
                    switch (format.charat(iformat)) {
                        case "d": case "m": case "y": case "@":
                        chars += "0123456789";
                        break;
                        case "d": case "m":
                        return null; // accept anything
                        case "'":
                            if (lookahead("'")) {
                                chars += "'";
                            } else {
                                literal = true;
                            }
                            break;
                        default:
                            chars += format.charat(iformat);
                    }
                }
            }
            return chars;
        },

        /* get a setting value, defaulting if necessary. */
        _get: function(inst, name) {
            return inst.settings[name] !== undefined ?
                inst.settings[name] : this._defaults[name];
        },

        /* parse existing date and initialise date picker. */
        _setdatefromfield: function(inst, nodefault) {
            if (inst.input.val() === inst.lastval) {
                return;
            }

            var dateformat = this._get(inst, "dateformat"),
                dates = inst.lastval = inst.input ? inst.input.val() : null,
                defaultdate = this._getdefaultdate(inst),
                date = defaultdate,
                settings = this._getformatconfig(inst);

            try {
                date = this.parsedate(dateformat, dates, settings) || defaultdate;
            } catch (event) {
                dates = (nodefault ? "" : dates);
            }
            inst.selectedday = date.getdate();
            inst.drawmonth = inst.selectedmonth = date.getmonth();
            inst.drawyear = inst.selectedyear = date.getfullyear();
            inst.currentday = (dates ? date.getdate() : 0);
            inst.currentmonth = (dates ? date.getmonth() : 0);
            inst.currentyear = (dates ? date.getfullyear() : 0);
            this._adjustinstdate(inst);
        },

        /* retrieve the default date shown on opening. */
        _getdefaultdate: function(inst) {
            return this._restrictminmax(inst,
                this._determinedate(inst, this._get(inst, "defaultdate"), new date()));
        },

        /* a date may be specified as an exact value or a relative one. */
        _determinedate: function(inst, date, defaultdate) {
            var offsetnumeric = function(offset) {
                    var date = new date();
                    date.setdate(date.getdate() + offset);
                    return date;
                },
                offsetstring = function(offset) {
                    try {
                        return $.datepicker.parsedate($.datepicker._get(inst, "dateformat"),
                            offset, $.datepicker._getformatconfig(inst));
                    }
                    catch (e) {
                        // ignore
                    }

                    var date = (offset.tolowercase().match(/^c/) ?
                            $.datepicker._getdate(inst) : null) || new date(),
                        year = date.getfullyear(),
                        month = date.getmonth(),
                        day = date.getdate(),
                        pattern = /([+\-]?[0-9]+)\s*(d|d|w|w|m|m|y|y)?/g,
                        matches = pattern.exec(offset);

                    while (matches) {
                        switch (matches[2] || "d") {
                            case "d" : case "d" :
                            day += parseint(matches[1],10); break;
                            case "w" : case "w" :
                            day += parseint(matches[1],10) * 7; break;
                            case "m" : case "m" :
                            month += parseint(matches[1],10);
                            day = math.min(day, $.datepicker._getdaysinmonth(year, month));
                            break;
                            case "y": case "y" :
                            year += parseint(matches[1],10);
                            day = math.min(day, $.datepicker._getdaysinmonth(year, month));
                            break;
                        }
                        matches = pattern.exec(offset);
                    }
                    return new date(year, month, day);
                },
                newdate = (date == null || date === "" ? defaultdate : (typeof date === "string" ? offsetstring(date) :
                    (typeof date === "number" ? (isnan(date) ? defaultdate : offsetnumeric(date)) : new date(date.gettime()))));

            newdate = (newdate && newdate.tostring() === "invalid date" ? defaultdate : newdate);
            if (newdate) {
                newdate.sethours(0);
                newdate.setminutes(0);
                newdate.setseconds(0);
                newdate.setmilliseconds(0);
            }
            return this._daylightsavingadjust(newdate);
        },

        /* handle switch to/from daylight saving.
         * hours may be non-zero on daylight saving cut-over:
         * > 12 when midnight changeover, but then cannot generate
         * midnight datetime, so jump to 1am, otherwise reset.
         * @param  date  (date) the date to check
         * @return  (date) the corrected date
         */
        _daylightsavingadjust: function(date) {
            if (!date) {
                return null;
            }
            date.sethours(date.gethours() > 12 ? date.gethours() + 2 : 0);
            return date;
        },

        /* set the date(s) directly. */
        _setdate: function(inst, date, nochange) {
            var clear = !date,
                origmonth = inst.selectedmonth,
                origyear = inst.selectedyear,
                newdate = this._restrictminmax(inst, this._determinedate(inst, date, new date()));

            inst.selectedday = inst.currentday = newdate.getdate();
            inst.drawmonth = inst.selectedmonth = inst.currentmonth = newdate.getmonth();
            inst.drawyear = inst.selectedyear = inst.currentyear = newdate.getfullyear();
            if ((origmonth !== inst.selectedmonth || origyear !== inst.selectedyear) && !nochange) {
                this._notifychange(inst);
            }
            this._adjustinstdate(inst);
            if (inst.input) {
                inst.input.val(clear ? "" : this._formatdate(inst));
            }
        },

        /* retrieve the date(s) directly. */
        _getdate: function(inst) {
            var startdate = (!inst.currentyear || (inst.input && inst.input.val() === "") ? null :
                this._daylightsavingadjust(new date(
                    inst.currentyear, inst.currentmonth, inst.currentday)));
            return startdate;
        },

        /* attach the onxxx handlers.  these are declared statically so
         * they work with static code transformers like caja.
         */
        _attachhandlers: function(inst) {
            var stepmonths = this._get(inst, "stepmonths"),
                id = "#" + inst.id.replace( /\\\\/g, "\\" );
            inst.dpdiv.find("[data-handler]").map(function () {
                var handler = {
                    prev: function () {
                        $.datepicker._adjustdate(id, -stepmonths, "m");
                    },
                    next: function () {
                        $.datepicker._adjustdate(id, +stepmonths, "m");
                    },
                    hide: function () {
                        $.datepicker._hidedatepicker();
                    },
                    today: function () {
                        $.datepicker._gototoday(id);
                    },
                    selectday: function () {
                        $.datepicker._selectday(id, +this.getattribute("data-month"), +this.getattribute("data-year"), this);
                        return false;
                    },
                    selectmonth: function () {
                        $.datepicker._selectmonthyear(id, this, "m");
                        return false;
                    },
                    selectyear: function () {
                        $.datepicker._selectmonthyear(id, this, "y");
                        return false;
                    }
                };
                $(this).bind(this.getattribute("data-event"), handler[this.getattribute("data-handler")]);
            });
        },

        /* generate the html for the current state of the date picker. */
        _generatehtml: function(inst) {
            var maxdraw, prevtext, prev, nexttext, next, currenttext, gotodate,
                controls, buttonpanel, firstday, showweek, daynames, daynamesmin,
                monthnames, monthnamesshort, beforeshowday, showothermonths,
                selectothermonths, defaultdate, html, dow, row, group, col, selecteddate,
                cornerclass, calender, thead, day, daysinmonth, leaddays, currows, numrows,
                printdate, drow, tbody, daysettings, othermonth, unselectable,
                tempdate = new date(),
                today = this._daylightsavingadjust(
                    new date(tempdate.getfullyear(), tempdate.getmonth(), tempdate.getdate())), // clear time
                isrtl = this._get(inst, "isrtl"),
                showbuttonpanel = this._get(inst, "showbuttonpanel"),
                hideifnoprevnext = this._get(inst, "hideifnoprevnext"),
                navigationasdateformat = this._get(inst, "navigationasdateformat"),
                nummonths = this._getnumberofmonths(inst),
                showcurrentatpos = this._get(inst, "showcurrentatpos"),
                stepmonths = this._get(inst, "stepmonths"),
                ismultimonth = (nummonths[0] !== 1 || nummonths[1] !== 1),
                currentdate = this._daylightsavingadjust((!inst.currentday ? new date(9999, 9, 9) :
                    new date(inst.currentyear, inst.currentmonth, inst.currentday))),
                mindate = this._getminmaxdate(inst, "min"),
                maxdate = this._getminmaxdate(inst, "max"),
                drawmonth = inst.drawmonth - showcurrentatpos,
                drawyear = inst.drawyear;

            if (drawmonth < 0) {
                drawmonth += 12;
                drawyear--;
            }
            if (maxdate) {
                maxdraw = this._daylightsavingadjust(new date(maxdate.getfullyear(),
                        maxdate.getmonth() - (nummonths[0] * nummonths[1]) + 1, maxdate.getdate()));
                maxdraw = (mindate && maxdraw < mindate ? mindate : maxdraw);
                while (this._daylightsavingadjust(new date(drawyear, drawmonth, 1)) > maxdraw) {
                    drawmonth--;
                    if (drawmonth < 0) {
                        drawmonth = 11;
                        drawyear--;
                    }
                }
            }
            inst.drawmonth = drawmonth;
            inst.drawyear = drawyear;

            prevtext = this._get(inst, "prevtext");
            prevtext = (!navigationasdateformat ? prevtext : this.formatdate(prevtext,
                this._daylightsavingadjust(new date(drawyear, drawmonth - stepmonths, 1)),
                this._getformatconfig(inst)));

            prev = (this._canadjustmonth(inst, -1, drawyear, drawmonth) ?
                "<a class='ui-datepicker-prev ui-corner-all' data-handler='prev' data-event='click'" +
                " title='" + prevtext + "'><span class='ui-icon ui-icon-circle-triangle-" + ( isrtl ? "e" : "w") + "'>" + prevtext + "</span></a>" :
                (hideifnoprevnext ? "" : "<a class='ui-datepicker-prev ui-corner-all ui-state-disabled' title='"+ prevtext +"'><span class='ui-icon ui-icon-circle-triangle-" + ( isrtl ? "e" : "w") + "'>" + prevtext + "</span></a>"));

            nexttext = this._get(inst, "nexttext");
            nexttext = (!navigationasdateformat ? nexttext : this.formatdate(nexttext,
                this._daylightsavingadjust(new date(drawyear, drawmonth + stepmonths, 1)),
                this._getformatconfig(inst)));

            next = (this._canadjustmonth(inst, +1, drawyear, drawmonth) ?
                "<a class='ui-datepicker-next ui-corner-all' data-handler='next' data-event='click'" +
                " title='" + nexttext + "'><span class='ui-icon ui-icon-circle-triangle-" + ( isrtl ? "w" : "e") + "'>" + nexttext + "</span></a>" :
                (hideifnoprevnext ? "" : "<a class='ui-datepicker-next ui-corner-all ui-state-disabled' title='"+ nexttext + "'><span class='ui-icon ui-icon-circle-triangle-" + ( isrtl ? "w" : "e") + "'>" + nexttext + "</span></a>"));

            currenttext = this._get(inst, "currenttext");
            gotodate = (this._get(inst, "gotocurrent") && inst.currentday ? currentdate : today);
            currenttext = (!navigationasdateformat ? currenttext :
                this.formatdate(currenttext, gotodate, this._getformatconfig(inst)));

            controls = (!inst.inline ? "<button type='button' class='ui-datepicker-close ui-state-default ui-priority-primary ui-corner-all' data-handler='hide' data-event='click'>" +
                this._get(inst, "closetext") + "</button>" : "");

            buttonpanel = (showbuttonpanel) ? "<div class='ui-datepicker-buttonpane ui-widget-content'>" + (isrtl ? controls : "") +
                (this._isinrange(inst, gotodate) ? "<button type='button' class='ui-datepicker-current ui-state-default ui-priority-secondary ui-corner-all' data-handler='today' data-event='click'" +
                    ">" + currenttext + "</button>" : "") + (isrtl ? "" : controls) + "</div>" : "";

            firstday = parseint(this._get(inst, "firstday"),10);
            firstday = (isnan(firstday) ? 0 : firstday);

            showweek = this._get(inst, "showweek");
            daynames = this._get(inst, "daynames");
            daynamesmin = this._get(inst, "daynamesmin");
            monthnames = this._get(inst, "monthnames");
            monthnamesshort = this._get(inst, "monthnamesshort");
            beforeshowday = this._get(inst, "beforeshowday");
            showothermonths = this._get(inst, "showothermonths");
            selectothermonths = this._get(inst, "selectothermonths");
            defaultdate = this._getdefaultdate(inst);
            html = "";
            dow;
            for (row = 0; row < nummonths[0]; row++) {
                group = "";
                this.maxrows = 4;
                for (col = 0; col < nummonths[1]; col++) {
                    selecteddate = this._daylightsavingadjust(new date(drawyear, drawmonth, inst.selectedday));
                    cornerclass = " ui-corner-all";
                    calender = "";
                    if (ismultimonth) {
                        calender += "<div class='ui-datepicker-group";
                        if (nummonths[1] > 1) {
                            switch (col) {
                                case 0: calender += " ui-datepicker-group-first";
                                    cornerclass = " ui-corner-" + (isrtl ? "right" : "left"); break;
                                case nummonths[1]-1: calender += " ui-datepicker-group-last";
                                    cornerclass = " ui-corner-" + (isrtl ? "left" : "right"); break;
                                default: calender += " ui-datepicker-group-middle"; cornerclass = ""; break;
                            }
                        }
                        calender += "'>";
                    }
                    calender += "<div class='ui-datepicker-header ui-widget-header ui-helper-clearfix" + cornerclass + "'>" +
                        (/all|left/.test(cornerclass) && row === 0 ? (isrtl ? next : prev) : "") +
                        (/all|right/.test(cornerclass) && row === 0 ? (isrtl ? prev : next) : "") +
                        this._generatemonthyearheader(inst, drawmonth, drawyear, mindate, maxdate,
                                row > 0 || col > 0, monthnames, monthnamesshort) + // draw month headers
                        "</div><table class='ui-datepicker-calendar'><thead>" +
                        "<tr>";
                    thead = (showweek ? "<th class='ui-datepicker-week-col'>" + this._get(inst, "weekheader") + "</th>" : "");
                    for (dow = 0; dow < 7; dow++) { // days of the week
                        day = (dow + firstday) % 7;
                        thead += "<th scope='col'" + ((dow + firstday + 6) % 7 >= 5 ? " class='ui-datepicker-week-end'" : "") + ">" +
                            "<span title='" + daynames[day] + "'>" + daynamesmin[day] + "</span></th>";
                    }
                    calender += thead + "</tr></thead><tbody>";
                    daysinmonth = this._getdaysinmonth(drawyear, drawmonth);
                    if (drawyear === inst.selectedyear && drawmonth === inst.selectedmonth) {
                        inst.selectedday = math.min(inst.selectedday, daysinmonth);
                    }
                    leaddays = (this._getfirstdayofmonth(drawyear, drawmonth) - firstday + 7) % 7;
                    currows = math.ceil((leaddays + daysinmonth) / 7); // calculate the number of rows to generate
                    numrows = (ismultimonth ? this.maxrows > currows ? this.maxrows : currows : currows); //if multiple months, use the higher number of rows (see #7043)
                    this.maxrows = numrows;
                    printdate = this._daylightsavingadjust(new date(drawyear, drawmonth, 1 - leaddays));
                    for (drow = 0; drow < numrows; drow++) { // create date picker rows
                        calender += "<tr>";
                        tbody = (!showweek ? "" : "<td class='ui-datepicker-week-col'>" +
                            this._get(inst, "calculateweek")(printdate) + "</td>");
                        for (dow = 0; dow < 7; dow++) { // create date picker days
                            daysettings = (beforeshowday ?
                                beforeshowday.apply((inst.input ? inst.input[0] : null), [printdate]) : [true, ""]);
                            othermonth = (printdate.getmonth() !== drawmonth);
                            unselectable = (othermonth && !selectothermonths) || !daysettings[0] ||
                                (mindate && printdate < mindate) || (maxdate && printdate > maxdate);
                            tbody += "<td class='" +
                                ((dow + firstday + 6) % 7 >= 5 ? " ui-datepicker-week-end" : "") + // highlight weekends
                                (othermonth ? " ui-datepicker-other-month" : "") + // highlight days from other months
                                ((printdate.gettime() === selecteddate.gettime() && drawmonth === inst.selectedmonth && inst._keyevent) || // user pressed key
                                    (defaultdate.gettime() === printdate.gettime() && defaultdate.gettime() === selecteddate.gettime()) ?
                                    // or defaultdate is current printeddate and defaultdate is selecteddate
                                    " " + this._dayoverclass : "") + // highlight selected day
                                (unselectable ? " " + this._unselectableclass + " ui-state-disabled": "") +  // highlight unselectable days
                                (othermonth && !showothermonths ? "" : " " + daysettings[1] + // highlight custom dates
                                    (printdate.gettime() === currentdate.gettime() ? " " + this._currentclass : "") + // highlight selected day
                                    (printdate.gettime() === today.gettime() ? " ui-datepicker-today" : "")) + "'" + // highlight today (if different)
                                ((!othermonth || showothermonths) && daysettings[2] ? " title='" + daysettings[2].replace(/'/g, "&#39;") + "'" : "") + // cell title
                                (unselectable ? "" : " data-handler='selectday' data-event='click' data-month='" + printdate.getmonth() + "' data-year='" + printdate.getfullyear() + "'") + ">" + // actions
                                (othermonth && !showothermonths ? "&#xa0;" : // display for other months
                                    (unselectable ? "<span class='ui-state-default'>" + printdate.getdate() + "</span>" : "<a class='ui-state-default" +
                                        (printdate.gettime() === today.gettime() ? " ui-state-highlight" : "") +
                                        (printdate.gettime() === currentdate.gettime() ? " ui-state-active" : "") + // highlight selected day
                                        (othermonth ? " ui-priority-secondary" : "") + // distinguish dates from other months
                                        "' href='#'>" + printdate.getdate() + "</a>")) + "</td>"; // display selectable date
                            printdate.setdate(printdate.getdate() + 1);
                            printdate = this._daylightsavingadjust(printdate);
                        }
                        calender += tbody + "</tr>";
                    }
                    drawmonth++;
                    if (drawmonth > 11) {
                        drawmonth = 0;
                        drawyear++;
                    }
                    calender += "</tbody></table>" + (ismultimonth ? "</div>" +
                        ((nummonths[0] > 0 && col === nummonths[1]-1) ? "<div class='ui-datepicker-row-break'></div>" : "") : "");
                    group += calender;
                }
                html += group;
            }
            html += buttonpanel;
            inst._keyevent = false;
            return html;
        },

        /* generate the month and year header. */
        _generatemonthyearheader: function(inst, drawmonth, drawyear, mindate, maxdate,
                                           secondary, monthnames, monthnamesshort) {

            var inminyear, inmaxyear, month, years, thisyear, determineyear, year, endyear,
                changemonth = this._get(inst, "changemonth"),
                changeyear = this._get(inst, "changeyear"),
                showmonthafteryear = this._get(inst, "showmonthafteryear"),
                html = "<div class='ui-datepicker-title'>",
                monthhtml = "";

            // month selection
            if (secondary || !changemonth) {
                monthhtml += "<span class='ui-datepicker-month'>" + monthnames[drawmonth] + "</span>";
            } else {
                inminyear = (mindate && mindate.getfullyear() === drawyear);
                inmaxyear = (maxdate && maxdate.getfullyear() === drawyear);
                monthhtml += "<select class='ui-datepicker-month' data-handler='selectmonth' data-event='change'>";
                for ( month = 0; month < 12; month++) {
                    if ((!inminyear || month >= mindate.getmonth()) && (!inmaxyear || month <= maxdate.getmonth())) {
                        monthhtml += "<option value='" + month + "'" +
                            (month === drawmonth ? " selected='selected'" : "") +
                            ">" + monthnamesshort[month] + "</option>";
                    }
                }
                monthhtml += "</select>";
            }

            if (!showmonthafteryear) {
                html += monthhtml + (secondary || !(changemonth && changeyear) ? "&#xa0;" : "");
            }

            // year selection
            if ( !inst.yearshtml ) {
                inst.yearshtml = "";
                if (secondary || !changeyear) {
                    html += "<span class='ui-datepicker-year'>" + drawyear + "</span>";
                } else {
                    // determine range of years to display
                    years = this._get(inst, "yearrange").split(":");
                    thisyear = new date().getfullyear();
                    determineyear = function(value) {
                        var year = (value.match(/c[+\-].*/) ? drawyear + parseint(value.substring(1), 10) :
                            (value.match(/[+\-].*/) ? thisyear + parseint(value, 10) :
                                parseint(value, 10)));
                        return (isnan(year) ? thisyear : year);
                    };
                    year = determineyear(years[0]);
                    endyear = math.max(year, determineyear(years[1] || ""));
                    year = (mindate ? math.max(year, mindate.getfullyear()) : year);
                    endyear = (maxdate ? math.min(endyear, maxdate.getfullyear()) : endyear);
                    inst.yearshtml += "<select class='ui-datepicker-year' data-handler='selectyear' data-event='change'>";
                    for (; year <= endyear; year++) {
                        inst.yearshtml += "<option value='" + year + "'" +
                            (year === drawyear ? " selected='selected'" : "") +
                            ">" + year + "</option>";
                    }
                    inst.yearshtml += "</select>";

                    html += inst.yearshtml;
                    inst.yearshtml = null;
                }
            }

            html += this._get(inst, "yearsuffix");
            if (showmonthafteryear) {
                html += (secondary || !(changemonth && changeyear) ? "&#xa0;" : "") + monthhtml;
            }
            html += "</div>"; // close datepicker_header
            return html;
        },

        /* adjust one of the date sub-fields. */
        _adjustinstdate: function(inst, offset, period) {
            var year = inst.drawyear + (period === "y" ? offset : 0),
                month = inst.drawmonth + (period === "m" ? offset : 0),
                day = math.min(inst.selectedday, this._getdaysinmonth(year, month)) + (period === "d" ? offset : 0),
                date = this._restrictminmax(inst, this._daylightsavingadjust(new date(year, month, day)));

            inst.selectedday = date.getdate();
            inst.drawmonth = inst.selectedmonth = date.getmonth();
            inst.drawyear = inst.selectedyear = date.getfullyear();
            if (period === "m" || period === "y") {
                this._notifychange(inst);
            }
        },

        /* ensure a date is within any min/max bounds. */
        _restrictminmax: function(inst, date) {
            var mindate = this._getminmaxdate(inst, "min"),
                maxdate = this._getminmaxdate(inst, "max"),
                newdate = (mindate && date < mindate ? mindate : date);
            return (maxdate && newdate > maxdate ? maxdate : newdate);
        },

        /* notify change of month/year. */
        _notifychange: function(inst) {
            var onchange = this._get(inst, "onchangemonthyear");
            if (onchange) {
                onchange.apply((inst.input ? inst.input[0] : null),
                    [inst.selectedyear, inst.selectedmonth + 1, inst]);
            }
        },

        /* determine the number of months to show. */
        _getnumberofmonths: function(inst) {
            var nummonths = this._get(inst, "numberofmonths");
            return (nummonths == null ? [1, 1] : (typeof nummonths === "number" ? [1, nummonths] : nummonths));
        },

        /* determine the current maximum date - ensure no time components are set. */
        _getminmaxdate: function(inst, minmax) {
            return this._determinedate(inst, this._get(inst, minmax + "date"), null);
        },

        /* find the number of days in a given month. */
        _getdaysinmonth: function(year, month) {
            return 32 - this._daylightsavingadjust(new date(year, month, 32)).getdate();
        },

        /* find the day of the week of the first of a month. */
        _getfirstdayofmonth: function(year, month) {
            return new date(year, month, 1).getday();
        },

        /* determines if we should allow a "next/prev" month display change. */
        _canadjustmonth: function(inst, offset, curyear, curmonth) {
            var nummonths = this._getnumberofmonths(inst),
                date = this._daylightsavingadjust(new date(curyear,
                        curmonth + (offset < 0 ? offset : nummonths[0] * nummonths[1]), 1));

            if (offset < 0) {
                date.setdate(this._getdaysinmonth(date.getfullyear(), date.getmonth()));
            }
            return this._isinrange(inst, date);
        },

        /* is the given date in the accepted range? */
        _isinrange: function(inst, date) {
            var yearsplit, currentyear,
                mindate = this._getminmaxdate(inst, "min"),
                maxdate = this._getminmaxdate(inst, "max"),
                minyear = null,
                maxyear = null,
                years = this._get(inst, "yearrange");
            if (years){
                yearsplit = years.split(":");
                currentyear = new date().getfullyear();
                minyear = parseint(yearsplit[0], 10);
                maxyear = parseint(yearsplit[1], 10);
                if ( yearsplit[0].match(/[+\-].*/) ) {
                    minyear += currentyear;
                }
                if ( yearsplit[1].match(/[+\-].*/) ) {
                    maxyear += currentyear;
                }
            }

            return ((!mindate || date.gettime() >= mindate.gettime()) &&
                (!maxdate || date.gettime() <= maxdate.gettime()) &&
                (!minyear || date.getfullyear() >= minyear) &&
                (!maxyear || date.getfullyear() <= maxyear));
        },

        /* provide the configuration settings for formatting/parsing. */
        _getformatconfig: function(inst) {
            var shortyearcutoff = this._get(inst, "shortyearcutoff");
            shortyearcutoff = (typeof shortyearcutoff !== "string" ? shortyearcutoff :
                new date().getfullyear() % 100 + parseint(shortyearcutoff, 10));
            return {shortyearcutoff: shortyearcutoff,
                daynamesshort: this._get(inst, "daynamesshort"), daynames: this._get(inst, "daynames"),
                monthnamesshort: this._get(inst, "monthnamesshort"), monthnames: this._get(inst, "monthnames")};
        },

        /* format the given date for display. */
        _formatdate: function(inst, day, month, year) {
            if (!day) {
                inst.currentday = inst.selectedday;
                inst.currentmonth = inst.selectedmonth;
                inst.currentyear = inst.selectedyear;
            }
            var date = (day ? (typeof day === "object" ? day :
                this._daylightsavingadjust(new date(year, month, day))) :
                this._daylightsavingadjust(new date(inst.currentyear, inst.currentmonth, inst.currentday)));
            return this.formatdate(this._get(inst, "dateformat"), date, this._getformatconfig(inst));
        }
    });

    /*
     * bind hover events for datepicker elements.
     * done via delegate so the binding only occurs once in the lifetime of the parent div.
     * global datepicker_instactive, set by _updatedatepicker allows the handlers to find their way back to the active picker.
     */
    function datepicker_bindhover(dpdiv) {
        var selector = "button, .ui-datepicker-prev, .ui-datepicker-next, .ui-datepicker-calendar td a";
        return dpdiv.delegate(selector, "mouseout", function() {
            $(this).removeclass("ui-state-hover");
            if (this.classname.indexof("ui-datepicker-prev") !== -1) {
                $(this).removeclass("ui-datepicker-prev-hover");
            }
            if (this.classname.indexof("ui-datepicker-next") !== -1) {
                $(this).removeclass("ui-datepicker-next-hover");
            }
        })
            .delegate( selector, "mouseover", datepicker_handlemouseover );
    }

    function datepicker_handlemouseover() {
        if (!$.datepicker._isdisableddatepicker( datepicker_instactive.inline? datepicker_instactive.dpdiv.parent()[0] : datepicker_instactive.input[0])) {
            $(this).parents(".ui-datepicker-calendar").find("a").removeclass("ui-state-hover");
            $(this).addclass("ui-state-hover");
            if (this.classname.indexof("ui-datepicker-prev") !== -1) {
                $(this).addclass("ui-datepicker-prev-hover");
            }
            if (this.classname.indexof("ui-datepicker-next") !== -1) {
                $(this).addclass("ui-datepicker-next-hover");
            }
        }
    }

    /* jquery extend now ignores nulls! */
    function datepicker_extendremove(target, props) {
        $.extend(target, props);
        for (var name in props) {
            if (props[name] == null) {
                target[name] = props[name];
            }
        }
        return target;
    }

    /* invoke the datepicker functionality.
     @param  options  string - a command, optionally followed by additional parameters or
     object - settings for attaching new datepicker functionality
     @return  jquery object */
    $.fn.datepicker = function(options){

        /* verify an empty collection wasn't passed - fixes #6976 */
        if ( !this.length ) {
            return this;
        }

        /* initialise the date picker. */
        if (!$.datepicker.initialized) {
            $(document).mousedown($.datepicker._checkexternalclick);
            $.datepicker.initialized = true;
        }

        /* append datepicker main container to body if not exist. */
        if ($("#"+$.datepicker._maindivid).length === 0) {
            $("body").append($.datepicker.dpdiv);
        }

        var otherargs = array.prototype.slice.call(arguments, 1);
        if (typeof options === "string" && (options === "isdisabled" || options === "getdate" || options === "widget")) {
            return $.datepicker["_" + options + "datepicker"].
                apply($.datepicker, [this[0]].concat(otherargs));
        }
        if (options === "option" && arguments.length === 2 && typeof arguments[1] === "string") {
            return $.datepicker["_" + options + "datepicker"].
                apply($.datepicker, [this[0]].concat(otherargs));
        }
        return this.each(function() {
            typeof options === "string" ?
                $.datepicker["_" + options + "datepicker"].
                    apply($.datepicker, [this].concat(otherargs)) :
                $.datepicker._attachdatepicker(this, options);
        });
    };

    $.datepicker = new datepicker(); // singleton instance
    $.datepicker.initialized = false;
    $.datepicker.uuid = new date().gettime();
    $.datepicker.version = "1.11.2";

    var datepicker = $.datepicker;


    /*!
     * jquery ui draggable 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/draggable/
     */


    $.widget("ui.draggable", $.ui.mouse, {
        version: "1.11.2",
        widgeteventprefix: "drag",
        options: {
            addclasses: true,
            appendto: "parent",
            axis: false,
            connecttosortable: false,
            containment: false,
            cursor: "auto",
            cursorat: false,
            grid: false,
            handle: false,
            helper: "original",
            iframefix: false,
            opacity: false,
            refreshpositions: false,
            revert: false,
            revertduration: 500,
            scope: "default",
            scroll: true,
            scrollsensitivity: 20,
            scrollspeed: 20,
            snap: false,
            snapmode: "both",
            snaptolerance: 20,
            stack: false,
            zindex: false,

            // callbacks
            drag: null,
            start: null,
            stop: null
        },
        _create: function() {

            if ( this.options.helper === "original" ) {
                this._setpositionrelative();
            }
            if (this.options.addclasses){
                this.element.addclass("ui-draggable");
            }
            if (this.options.disabled){
                this.element.addclass("ui-draggable-disabled");
            }
            this._sethandleclassname();

            this._mouseinit();
        },

        _setoption: function( key, value ) {
            this._super( key, value );
            if ( key === "handle" ) {
                this._removehandleclassname();
                this._sethandleclassname();
            }
        },

        _destroy: function() {
            if ( ( this.helper || this.element ).is( ".ui-draggable-dragging" ) ) {
                this.destroyonclear = true;
                return;
            }
            this.element.removeclass( "ui-draggable ui-draggable-dragging ui-draggable-disabled" );
            this._removehandleclassname();
            this._mousedestroy();
        },

        _mousecapture: function(event) {
            var o = this.options;

            this._bluractiveelement( event );

            // among others, prevent a drag on a resizable-handle
            if (this.helper || o.disabled || $(event.target).closest(".ui-resizable-handle").length > 0) {
                return false;
            }

            //quit if we're not on a valid handle
            this.handle = this._gethandle(event);
            if (!this.handle) {
                return false;
            }

            this._blockframes( o.iframefix === true ? "iframe" : o.iframefix );

            return true;

        },

        _blockframes: function( selector ) {
            this.iframeblocks = this.document.find( selector ).map(function() {
                var iframe = $( this );

                return $( "<div>" )
                    .css( "position", "absolute" )
                    .appendto( iframe.parent() )
                    .outerwidth( iframe.outerwidth() )
                    .outerheight( iframe.outerheight() )
                    .offset( iframe.offset() )[ 0 ];
            });
        },

        _unblockframes: function() {
            if ( this.iframeblocks ) {
                this.iframeblocks.remove();
                delete this.iframeblocks;
            }
        },

        _bluractiveelement: function( event ) {
            var document = this.document[ 0 ];

            // only need to blur if the event occurred on the draggable itself, see #10527
            if ( !this.handleelement.is( event.target ) ) {
                return;
            }

            // support: ie9
            // ie9 throws an "unspecified error" accessing document.activeelement from an <iframe>
            try {

                // support: ie9, ie10
                // if the <body> is blurred, ie will switch windows, see #9520
                if ( document.activeelement && document.activeelement.nodename.tolowercase() !== "body" ) {

                    // blur any element that currently has focus, see #4261
                    $( document.activeelement ).blur();
                }
            } catch ( error ) {}
        },

        _mousestart: function(event) {

            var o = this.options;

            //create and append the visible helper
            this.helper = this._createhelper(event);

            this.helper.addclass("ui-draggable-dragging");

            //cache the helper size
            this._cachehelperproportions();

            //if ddmanager is used for droppables, set the global draggable
            if ($.ui.ddmanager) {
                $.ui.ddmanager.current = this;
            }

            /*
             * - position generation -
             * this block generates everything position related - it's the core of draggables.
             */

            //cache the margins of the original element
            this._cachemargins();

            //store the helper's css position
            this.cssposition = this.helper.css( "position" );
            this.scrollparent = this.helper.scrollparent( true );
            this.offsetparent = this.helper.offsetparent();
            this.hasfixedancestor = this.helper.parents().filter(function() {
                return $( this ).css( "position" ) === "fixed";
            }).length > 0;

            //the element's absolute position on the page minus margins
            this.positionabs = this.element.offset();
            this._refreshoffsets( event );

            //generate the original position
            this.originalposition = this.position = this._generateposition( event, false );
            this.originalpagex = event.pagex;
            this.originalpagey = event.pagey;

            //adjust the mouse offset relative to the helper if "cursorat" is supplied
            (o.cursorat && this._adjustoffsetfromhelper(o.cursorat));

            //set a containment if given in the options
            this._setcontainment();

            //trigger event + callbacks
            if (this._trigger("start", event) === false) {
                this._clear();
                return false;
            }

            //recache the helper size
            this._cachehelperproportions();

            //prepare the droppable offsets
            if ($.ui.ddmanager && !o.dropbehaviour) {
                $.ui.ddmanager.prepareoffsets(this, event);
            }

            // reset helper's right/bottom css if they're set and set explicit width/height instead
            // as this prevents resizing of elements with right/bottom set (see #7772)
            this._normalizerightbottom();

            this._mousedrag(event, true); //execute the drag once - this causes the helper not to be visible before getting its correct position

            //if the ddmanager is used for droppables, inform the manager that dragging has started (see #5003)
            if ( $.ui.ddmanager ) {
                $.ui.ddmanager.dragstart(this, event);
            }

            return true;
        },

        _refreshoffsets: function( event ) {
            this.offset = {
                top: this.positionabs.top - this.margins.top,
                left: this.positionabs.left - this.margins.left,
                scroll: false,
                parent: this._getparentoffset(),
                relative: this._getrelativeoffset()
            };

            this.offset.click = {
                left: event.pagex - this.offset.left,
                top: event.pagey - this.offset.top
            };
        },

        _mousedrag: function(event, nopropagation) {
            // reset any necessary cached properties (see #5009)
            if ( this.hasfixedancestor ) {
                this.offset.parent = this._getparentoffset();
            }

            //compute the helpers position
            this.position = this._generateposition( event, true );
            this.positionabs = this._convertpositionto("absolute");

            //call plugins and callbacks and use the resulting position if something is returned
            if (!nopropagation) {
                var ui = this._uihash();
                if (this._trigger("drag", event, ui) === false) {
                    this._mouseup({});
                    return false;
                }
                this.position = ui.position;
            }

            this.helper[ 0 ].style.left = this.position.left + "px";
            this.helper[ 0 ].style.top = this.position.top + "px";

            if ($.ui.ddmanager) {
                $.ui.ddmanager.drag(this, event);
            }

            return false;
        },

        _mousestop: function(event) {

            //if we are using droppables, inform the manager about the drop
            var that = this,
                dropped = false;
            if ($.ui.ddmanager && !this.options.dropbehaviour) {
                dropped = $.ui.ddmanager.drop(this, event);
            }

            //if a drop comes from outside (a sortable)
            if (this.dropped) {
                dropped = this.dropped;
                this.dropped = false;
            }

            if ((this.options.revert === "invalid" && !dropped) || (this.options.revert === "valid" && dropped) || this.options.revert === true || ($.isfunction(this.options.revert) && this.options.revert.call(this.element, dropped))) {
                $(this.helper).animate(this.originalposition, parseint(this.options.revertduration, 10), function() {
                    if (that._trigger("stop", event) !== false) {
                        that._clear();
                    }
                });
            } else {
                if (this._trigger("stop", event) !== false) {
                    this._clear();
                }
            }

            return false;
        },

        _mouseup: function( event ) {
            this._unblockframes();

            //if the ddmanager is used for droppables, inform the manager that dragging has stopped (see #5003)
            if ( $.ui.ddmanager ) {
                $.ui.ddmanager.dragstop(this, event);
            }

            // only need to focus if the event occurred on the draggable itself, see #10527
            if ( this.handleelement.is( event.target ) ) {
                // the interaction is over; whether or not the click resulted in a drag, focus the element
                this.element.focus();
            }

            return $.ui.mouse.prototype._mouseup.call(this, event);
        },

        cancel: function() {

            if (this.helper.is(".ui-draggable-dragging")) {
                this._mouseup({});
            } else {
                this._clear();
            }

            return this;

        },

        _gethandle: function(event) {
            return this.options.handle ?
                !!$( event.target ).closest( this.element.find( this.options.handle ) ).length :
                true;
        },

        _sethandleclassname: function() {
            this.handleelement = this.options.handle ?
                this.element.find( this.options.handle ) : this.element;
            this.handleelement.addclass( "ui-draggable-handle" );
        },

        _removehandleclassname: function() {
            this.handleelement.removeclass( "ui-draggable-handle" );
        },

        _createhelper: function(event) {

            var o = this.options,
                helperisfunction = $.isfunction( o.helper ),
                helper = helperisfunction ?
                    $( o.helper.apply( this.element[ 0 ], [ event ] ) ) :
                    ( o.helper === "clone" ?
                        this.element.clone().removeattr( "id" ) :
                        this.element );

            if (!helper.parents("body").length) {
                helper.appendto((o.appendto === "parent" ? this.element[0].parentnode : o.appendto));
            }

            // http://bugs.jqueryui.com/ticket/9446
            // a helper function can return the original element
            // which wouldn't have been set to relative in _create
            if ( helperisfunction && helper[ 0 ] === this.element[ 0 ] ) {
                this._setpositionrelative();
            }

            if (helper[0] !== this.element[0] && !(/(fixed|absolute)/).test(helper.css("position"))) {
                helper.css("position", "absolute");
            }

            return helper;

        },

        _setpositionrelative: function() {
            if ( !( /^(?:r|a|f)/ ).test( this.element.css( "position" ) ) ) {
                this.element[ 0 ].style.position = "relative";
            }
        },

        _adjustoffsetfromhelper: function(obj) {
            if (typeof obj === "string") {
                obj = obj.split(" ");
            }
            if ($.isarray(obj)) {
                obj = { left: +obj[0], top: +obj[1] || 0 };
            }
            if ("left" in obj) {
                this.offset.click.left = obj.left + this.margins.left;
            }
            if ("right" in obj) {
                this.offset.click.left = this.helperproportions.width - obj.right + this.margins.left;
            }
            if ("top" in obj) {
                this.offset.click.top = obj.top + this.margins.top;
            }
            if ("bottom" in obj) {
                this.offset.click.top = this.helperproportions.height - obj.bottom + this.margins.top;
            }
        },

        _isrootnode: function( element ) {
            return ( /(html|body)/i ).test( element.tagname ) || element === this.document[ 0 ];
        },

        _getparentoffset: function() {

            //get the offsetparent and cache its position
            var po = this.offsetparent.offset(),
                document = this.document[ 0 ];

            // this is a special case where we need to modify a offset calculated on start, since the following happened:
            // 1. the position of the helper is absolute, so it's position is calculated based on the next positioned parent
            // 2. the actual offset parent is a child of the scroll parent, and the scroll parent isn't the document, which means that
            //    the scroll is included in the initial calculation of the offset of the parent, and never recalculated upon drag
            if (this.cssposition === "absolute" && this.scrollparent[0] !== document && $.contains(this.scrollparent[0], this.offsetparent[0])) {
                po.left += this.scrollparent.scrollleft();
                po.top += this.scrollparent.scrolltop();
            }

            if ( this._isrootnode( this.offsetparent[ 0 ] ) ) {
                po = { top: 0, left: 0 };
            }

            return {
                top: po.top + (parseint(this.offsetparent.css("bordertopwidth"), 10) || 0),
                left: po.left + (parseint(this.offsetparent.css("borderleftwidth"), 10) || 0)
            };

        },

        _getrelativeoffset: function() {
            if ( this.cssposition !== "relative" ) {
                return { top: 0, left: 0 };
            }

            var p = this.element.position(),
                scrollisrootnode = this._isrootnode( this.scrollparent[ 0 ] );

            return {
                top: p.top - ( parseint(this.helper.css( "top" ), 10) || 0 ) + ( !scrollisrootnode ? this.scrollparent.scrolltop() : 0 ),
                left: p.left - ( parseint(this.helper.css( "left" ), 10) || 0 ) + ( !scrollisrootnode ? this.scrollparent.scrollleft() : 0 )
            };

        },

        _cachemargins: function() {
            this.margins = {
                left: (parseint(this.element.css("marginleft"), 10) || 0),
                top: (parseint(this.element.css("margintop"), 10) || 0),
                right: (parseint(this.element.css("marginright"), 10) || 0),
                bottom: (parseint(this.element.css("marginbottom"), 10) || 0)
            };
        },

        _cachehelperproportions: function() {
            this.helperproportions = {
                width: this.helper.outerwidth(),
                height: this.helper.outerheight()
            };
        },

        _setcontainment: function() {

            var isuserscrollable, c, ce,
                o = this.options,
                document = this.document[ 0 ];

            this.relativecontainer = null;

            if ( !o.containment ) {
                this.containment = null;
                return;
            }

            if ( o.containment === "window" ) {
                this.containment = [
                        $( window ).scrollleft() - this.offset.relative.left - this.offset.parent.left,
                        $( window ).scrolltop() - this.offset.relative.top - this.offset.parent.top,
                        $( window ).scrollleft() + $( window ).width() - this.helperproportions.width - this.margins.left,
                        $( window ).scrolltop() + ( $( window ).height() || document.body.parentnode.scrollheight ) - this.helperproportions.height - this.margins.top
                ];
                return;
            }

            if ( o.containment === "document") {
                this.containment = [
                    0,
                    0,
                        $( document ).width() - this.helperproportions.width - this.margins.left,
                        ( $( document ).height() || document.body.parentnode.scrollheight ) - this.helperproportions.height - this.margins.top
                ];
                return;
            }

            if ( o.containment.constructor === array ) {
                this.containment = o.containment;
                return;
            }

            if ( o.containment === "parent" ) {
                o.containment = this.helper[ 0 ].parentnode;
            }

            c = $( o.containment );
            ce = c[ 0 ];

            if ( !ce ) {
                return;
            }

            isuserscrollable = /(scroll|auto)/.test( c.css( "overflow" ) );

            this.containment = [
                    ( parseint( c.css( "borderleftwidth" ), 10 ) || 0 ) + ( parseint( c.css( "paddingleft" ), 10 ) || 0 ),
                    ( parseint( c.css( "bordertopwidth" ), 10 ) || 0 ) + ( parseint( c.css( "paddingtop" ), 10 ) || 0 ),
                    ( isuserscrollable ? math.max( ce.scrollwidth, ce.offsetwidth ) : ce.offsetwidth ) -
                    ( parseint( c.css( "borderrightwidth" ), 10 ) || 0 ) -
                    ( parseint( c.css( "paddingright" ), 10 ) || 0 ) -
                    this.helperproportions.width -
                    this.margins.left -
                    this.margins.right,
                    ( isuserscrollable ? math.max( ce.scrollheight, ce.offsetheight ) : ce.offsetheight ) -
                    ( parseint( c.css( "borderbottomwidth" ), 10 ) || 0 ) -
                    ( parseint( c.css( "paddingbottom" ), 10 ) || 0 ) -
                    this.helperproportions.height -
                    this.margins.top -
                    this.margins.bottom
            ];
            this.relativecontainer = c;
        },

        _convertpositionto: function(d, pos) {

            if (!pos) {
                pos = this.position;
            }

            var mod = d === "absolute" ? 1 : -1,
                scrollisrootnode = this._isrootnode( this.scrollparent[ 0 ] );

            return {
                top: (
                    pos.top	+																// the absolute mouse position
                    this.offset.relative.top * mod +										// only for relative positioned nodes: relative offset from element to offset parent
                    this.offset.parent.top * mod -										// the offsetparent's offset without borders (offset + border)
                    ( ( this.cssposition === "fixed" ? -this.offset.scroll.top : ( scrollisrootnode ? 0 : this.offset.scroll.top ) ) * mod)
                    ),
                left: (
                    pos.left +																// the absolute mouse position
                    this.offset.relative.left * mod +										// only for relative positioned nodes: relative offset from element to offset parent
                    this.offset.parent.left * mod	-										// the offsetparent's offset without borders (offset + border)
                    ( ( this.cssposition === "fixed" ? -this.offset.scroll.left : ( scrollisrootnode ? 0 : this.offset.scroll.left ) ) * mod)
                    )
            };

        },

        _generateposition: function( event, constrainposition ) {

            var containment, co, top, left,
                o = this.options,
                scrollisrootnode = this._isrootnode( this.scrollparent[ 0 ] ),
                pagex = event.pagex,
                pagey = event.pagey;

            // cache the scroll
            if ( !scrollisrootnode || !this.offset.scroll ) {
                this.offset.scroll = {
                    top: this.scrollparent.scrolltop(),
                    left: this.scrollparent.scrollleft()
                };
            }

            /*
             * - position constraining -
             * constrain the position to a mix of grid, containment.
             */

            // if we are not dragging yet, we won't check for options
            if ( constrainposition ) {
                if ( this.containment ) {
                    if ( this.relativecontainer ){
                        co = this.relativecontainer.offset();
                        containment = [
                                this.containment[ 0 ] + co.left,
                                this.containment[ 1 ] + co.top,
                                this.containment[ 2 ] + co.left,
                                this.containment[ 3 ] + co.top
                        ];
                    } else {
                        containment = this.containment;
                    }

                    if (event.pagex - this.offset.click.left < containment[0]) {
                        pagex = containment[0] + this.offset.click.left;
                    }
                    if (event.pagey - this.offset.click.top < containment[1]) {
                        pagey = containment[1] + this.offset.click.top;
                    }
                    if (event.pagex - this.offset.click.left > containment[2]) {
                        pagex = containment[2] + this.offset.click.left;
                    }
                    if (event.pagey - this.offset.click.top > containment[3]) {
                        pagey = containment[3] + this.offset.click.top;
                    }
                }

                if (o.grid) {
                    //check for grid elements set to 0 to prevent divide by 0 error causing invalid argument errors in ie (see ticket #6950)
                    top = o.grid[1] ? this.originalpagey + math.round((pagey - this.originalpagey) / o.grid[1]) * o.grid[1] : this.originalpagey;
                    pagey = containment ? ((top - this.offset.click.top >= containment[1] || top - this.offset.click.top > containment[3]) ? top : ((top - this.offset.click.top >= containment[1]) ? top - o.grid[1] : top + o.grid[1])) : top;

                    left = o.grid[0] ? this.originalpagex + math.round((pagex - this.originalpagex) / o.grid[0]) * o.grid[0] : this.originalpagex;
                    pagex = containment ? ((left - this.offset.click.left >= containment[0] || left - this.offset.click.left > containment[2]) ? left : ((left - this.offset.click.left >= containment[0]) ? left - o.grid[0] : left + o.grid[0])) : left;
                }

                if ( o.axis === "y" ) {
                    pagex = this.originalpagex;
                }

                if ( o.axis === "x" ) {
                    pagey = this.originalpagey;
                }
            }

            return {
                top: (
                    pagey -																	// the absolute mouse position
                    this.offset.click.top	-												// click offset (relative to the element)
                    this.offset.relative.top -												// only for relative positioned nodes: relative offset from element to offset parent
                    this.offset.parent.top +												// the offsetparent's offset without borders (offset + border)
                    ( this.cssposition === "fixed" ? -this.offset.scroll.top : ( scrollisrootnode ? 0 : this.offset.scroll.top ) )
                    ),
                left: (
                    pagex -																	// the absolute mouse position
                    this.offset.click.left -												// click offset (relative to the element)
                    this.offset.relative.left -												// only for relative positioned nodes: relative offset from element to offset parent
                    this.offset.parent.left +												// the offsetparent's offset without borders (offset + border)
                    ( this.cssposition === "fixed" ? -this.offset.scroll.left : ( scrollisrootnode ? 0 : this.offset.scroll.left ) )
                    )
            };

        },

        _clear: function() {
            this.helper.removeclass("ui-draggable-dragging");
            if (this.helper[0] !== this.element[0] && !this.cancelhelperremoval) {
                this.helper.remove();
            }
            this.helper = null;
            this.cancelhelperremoval = false;
            if ( this.destroyonclear ) {
                this.destroy();
            }
        },

        _normalizerightbottom: function() {
            if ( this.options.axis !== "y" && this.helper.css( "right" ) !== "auto" ) {
                this.helper.width( this.helper.width() );
                this.helper.css( "right", "auto" );
            }
            if ( this.options.axis !== "x" && this.helper.css( "bottom" ) !== "auto" ) {
                this.helper.height( this.helper.height() );
                this.helper.css( "bottom", "auto" );
            }
        },

        // from now on bulk stuff - mainly helpers

        _trigger: function( type, event, ui ) {
            ui = ui || this._uihash();
            $.ui.plugin.call( this, type, [ event, ui, this ], true );

            // absolute position and offset (see #6884 ) have to be recalculated after plugins
            if ( /^(drag|start|stop)/.test( type ) ) {
                this.positionabs = this._convertpositionto( "absolute" );
                ui.offset = this.positionabs;
            }
            return $.widget.prototype._trigger.call( this, type, event, ui );
        },

        plugins: {},

        _uihash: function() {
            return {
                helper: this.helper,
                position: this.position,
                originalposition: this.originalposition,
                offset: this.positionabs
            };
        }

    });

    $.ui.plugin.add( "draggable", "connecttosortable", {
        start: function( event, ui, draggable ) {
            var uisortable = $.extend( {}, ui, {
                item: draggable.element
            });

            draggable.sortables = [];
            $( draggable.options.connecttosortable ).each(function() {
                var sortable = $( this ).sortable( "instance" );

                if ( sortable && !sortable.options.disabled ) {
                    draggable.sortables.push( sortable );

                    // refreshpositions is called at drag start to refresh the containercache
                    // which is used in drag. this ensures it's initialized and synchronized
                    // with any changes that might have happened on the page since initialization.
                    sortable.refreshpositions();
                    sortable._trigger("activate", event, uisortable);
                }
            });
        },
        stop: function( event, ui, draggable ) {
            var uisortable = $.extend( {}, ui, {
                item: draggable.element
            });

            draggable.cancelhelperremoval = false;

            $.each( draggable.sortables, function() {
                var sortable = this;

                if ( sortable.isover ) {
                    sortable.isover = 0;

                    // allow this sortable to handle removing the helper
                    draggable.cancelhelperremoval = true;
                    sortable.cancelhelperremoval = false;

                    // use _storedcss to restore properties in the sortable,
                    // as this also handles revert (#9675) since the draggable
                    // may have modified them in unexpected ways (#8809)
                    sortable._storedcss = {
                        position: sortable.placeholder.css( "position" ),
                        top: sortable.placeholder.css( "top" ),
                        left: sortable.placeholder.css( "left" )
                    };

                    sortable._mousestop(event);

                    // once drag has ended, the sortable should return to using
                    // its original helper, not the shared helper from draggable
                    sortable.options.helper = sortable.options._helper;
                } else {
                    // prevent this sortable from removing the helper.
                    // however, don't set the draggable to remove the helper
                    // either as another connected sortable may yet handle the removal.
                    sortable.cancelhelperremoval = true;

                    sortable._trigger( "deactivate", event, uisortable );
                }
            });
        },
        drag: function( event, ui, draggable ) {
            $.each( draggable.sortables, function() {
                var innermostintersecting = false,
                    sortable = this;

                // copy over variables that sortable's _intersectswith uses
                sortable.positionabs = draggable.positionabs;
                sortable.helperproportions = draggable.helperproportions;
                sortable.offset.click = draggable.offset.click;

                if ( sortable._intersectswith( sortable.containercache ) ) {
                    innermostintersecting = true;

                    $.each( draggable.sortables, function() {
                        // copy over variables that sortable's _intersectswith uses
                        this.positionabs = draggable.positionabs;
                        this.helperproportions = draggable.helperproportions;
                        this.offset.click = draggable.offset.click;

                        if ( this !== sortable &&
                            this._intersectswith( this.containercache ) &&
                            $.contains( sortable.element[ 0 ], this.element[ 0 ] ) ) {
                            innermostintersecting = false;
                        }

                        return innermostintersecting;
                    });
                }

                if ( innermostintersecting ) {
                    // if it intersects, we use a little isover variable and set it once,
                    // so that the move-in stuff gets fired only once.
                    if ( !sortable.isover ) {
                        sortable.isover = 1;

                        sortable.currentitem = ui.helper
                            .appendto( sortable.element )
                            .data( "ui-sortable-item", true );

                        // store helper option to later restore it
                        sortable.options._helper = sortable.options.helper;

                        sortable.options.helper = function() {
                            return ui.helper[ 0 ];
                        };

                        // fire the start events of the sortable with our passed browser event,
                        // and our own helper (so it doesn't create a new one)
                        event.target = sortable.currentitem[ 0 ];
                        sortable._mousecapture( event, true );
                        sortable._mousestart( event, true, true );

                        // because the browser event is way off the new appended portlet,
                        // modify necessary variables to reflect the changes
                        sortable.offset.click.top = draggable.offset.click.top;
                        sortable.offset.click.left = draggable.offset.click.left;
                        sortable.offset.parent.left -= draggable.offset.parent.left -
                            sortable.offset.parent.left;
                        sortable.offset.parent.top -= draggable.offset.parent.top -
                            sortable.offset.parent.top;

                        draggable._trigger( "tosortable", event );

                        // inform draggable that the helper is in a valid drop zone,
                        // used solely in the revert option to handle "valid/invalid".
                        draggable.dropped = sortable.element;

                        // need to refreshpositions of all sortables in the case that
                        // adding to one sortable changes the location of the other sortables (#9675)
                        $.each( draggable.sortables, function() {
                            this.refreshpositions();
                        });

                        // hack so receive/update callbacks work (mostly)
                        draggable.currentitem = draggable.element;
                        sortable.fromoutside = draggable;
                    }

                    if ( sortable.currentitem ) {
                        sortable._mousedrag( event );
                        // copy the sortable's position because the draggable's can potentially reflect
                        // a relative position, while sortable is always absolute, which the dragged
                        // element has now become. (#8809)
                        ui.position = sortable.position;
                    }
                } else {
                    // if it doesn't intersect with the sortable, and it intersected before,
                    // we fake the drag stop of the sortable, but make sure it doesn't remove
                    // the helper by using cancelhelperremoval.
                    if ( sortable.isover ) {

                        sortable.isover = 0;
                        sortable.cancelhelperremoval = true;

                        // calling sortable's mousestop would trigger a revert,
                        // so revert must be temporarily false until after mousestop is called.
                        sortable.options._revert = sortable.options.revert;
                        sortable.options.revert = false;

                        sortable._trigger( "out", event, sortable._uihash( sortable ) );
                        sortable._mousestop( event, true );

                        // restore sortable behaviors that were modfied
                        // when the draggable entered the sortable area (#9481)
                        sortable.options.revert = sortable.options._revert;
                        sortable.options.helper = sortable.options._helper;

                        if ( sortable.placeholder ) {
                            sortable.placeholder.remove();
                        }

                        // recalculate the draggable's offset considering the sortable
                        // may have modified them in unexpected ways (#8809)
                        draggable._refreshoffsets( event );
                        ui.position = draggable._generateposition( event, true );

                        draggable._trigger( "fromsortable", event );

                        // inform draggable that the helper is no longer in a valid drop zone
                        draggable.dropped = false;

                        // need to refreshpositions of all sortables just in case removing
                        // from one sortable changes the location of other sortables (#9675)
                        $.each( draggable.sortables, function() {
                            this.refreshpositions();
                        });
                    }
                }
            });
        }
    });

    $.ui.plugin.add("draggable", "cursor", {
        start: function( event, ui, instance ) {
            var t = $( "body" ),
                o = instance.options;

            if (t.css("cursor")) {
                o._cursor = t.css("cursor");
            }
            t.css("cursor", o.cursor);
        },
        stop: function( event, ui, instance ) {
            var o = instance.options;
            if (o._cursor) {
                $("body").css("cursor", o._cursor);
            }
        }
    });

    $.ui.plugin.add("draggable", "opacity", {
        start: function( event, ui, instance ) {
            var t = $( ui.helper ),
                o = instance.options;
            if (t.css("opacity")) {
                o._opacity = t.css("opacity");
            }
            t.css("opacity", o.opacity);
        },
        stop: function( event, ui, instance ) {
            var o = instance.options;
            if (o._opacity) {
                $(ui.helper).css("opacity", o._opacity);
            }
        }
    });

    $.ui.plugin.add("draggable", "scroll", {
        start: function( event, ui, i ) {
            if ( !i.scrollparentnothidden ) {
                i.scrollparentnothidden = i.helper.scrollparent( false );
            }

            if ( i.scrollparentnothidden[ 0 ] !== i.document[ 0 ] && i.scrollparentnothidden[ 0 ].tagname !== "html" ) {
                i.overflowoffset = i.scrollparentnothidden.offset();
            }
        },
        drag: function( event, ui, i  ) {

            var o = i.options,
                scrolled = false,
                scrollparent = i.scrollparentnothidden[ 0 ],
                document = i.document[ 0 ];

            if ( scrollparent !== document && scrollparent.tagname !== "html" ) {
                if ( !o.axis || o.axis !== "x" ) {
                    if ( ( i.overflowoffset.top + scrollparent.offsetheight ) - event.pagey < o.scrollsensitivity ) {
                        scrollparent.scrolltop = scrolled = scrollparent.scrolltop + o.scrollspeed;
                    } else if ( event.pagey - i.overflowoffset.top < o.scrollsensitivity ) {
                        scrollparent.scrolltop = scrolled = scrollparent.scrolltop - o.scrollspeed;
                    }
                }

                if ( !o.axis || o.axis !== "y" ) {
                    if ( ( i.overflowoffset.left + scrollparent.offsetwidth ) - event.pagex < o.scrollsensitivity ) {
                        scrollparent.scrollleft = scrolled = scrollparent.scrollleft + o.scrollspeed;
                    } else if ( event.pagex - i.overflowoffset.left < o.scrollsensitivity ) {
                        scrollparent.scrollleft = scrolled = scrollparent.scrollleft - o.scrollspeed;
                    }
                }

            } else {

                if (!o.axis || o.axis !== "x") {
                    if (event.pagey - $(document).scrolltop() < o.scrollsensitivity) {
                        scrolled = $(document).scrolltop($(document).scrolltop() - o.scrollspeed);
                    } else if ($(window).height() - (event.pagey - $(document).scrolltop()) < o.scrollsensitivity) {
                        scrolled = $(document).scrolltop($(document).scrolltop() + o.scrollspeed);
                    }
                }

                if (!o.axis || o.axis !== "y") {
                    if (event.pagex - $(document).scrollleft() < o.scrollsensitivity) {
                        scrolled = $(document).scrollleft($(document).scrollleft() - o.scrollspeed);
                    } else if ($(window).width() - (event.pagex - $(document).scrollleft()) < o.scrollsensitivity) {
                        scrolled = $(document).scrollleft($(document).scrollleft() + o.scrollspeed);
                    }
                }

            }

            if (scrolled !== false && $.ui.ddmanager && !o.dropbehaviour) {
                $.ui.ddmanager.prepareoffsets(i, event);
            }

        }
    });

    $.ui.plugin.add("draggable", "snap", {
        start: function( event, ui, i ) {

            var o = i.options;

            i.snapelements = [];

            $(o.snap.constructor !== string ? ( o.snap.items || ":data(ui-draggable)" ) : o.snap).each(function() {
                var $t = $(this),
                    $o = $t.offset();
                if (this !== i.element[0]) {
                    i.snapelements.push({
                        item: this,
                        width: $t.outerwidth(), height: $t.outerheight(),
                        top: $o.top, left: $o.left
                    });
                }
            });

        },
        drag: function( event, ui, inst ) {

            var ts, bs, ls, rs, l, r, t, b, i, first,
                o = inst.options,
                d = o.snaptolerance,
                x1 = ui.offset.left, x2 = x1 + inst.helperproportions.width,
                y1 = ui.offset.top, y2 = y1 + inst.helperproportions.height;

            for (i = inst.snapelements.length - 1; i >= 0; i--){

                l = inst.snapelements[i].left - inst.margins.left;
                r = l + inst.snapelements[i].width;
                t = inst.snapelements[i].top - inst.margins.top;
                b = t + inst.snapelements[i].height;

                if ( x2 < l - d || x1 > r + d || y2 < t - d || y1 > b + d || !$.contains( inst.snapelements[ i ].item.ownerdocument, inst.snapelements[ i ].item ) ) {
                    if (inst.snapelements[i].snapping) {
                        (inst.options.snap.release && inst.options.snap.release.call(inst.element, event, $.extend(inst._uihash(), { snapitem: inst.snapelements[i].item })));
                    }
                    inst.snapelements[i].snapping = false;
                    continue;
                }

                if (o.snapmode !== "inner") {
                    ts = math.abs(t - y2) <= d;
                    bs = math.abs(b - y1) <= d;
                    ls = math.abs(l - x2) <= d;
                    rs = math.abs(r - x1) <= d;
                    if (ts) {
                        ui.position.top = inst._convertpositionto("relative", { top: t - inst.helperproportions.height, left: 0 }).top;
                    }
                    if (bs) {
                        ui.position.top = inst._convertpositionto("relative", { top: b, left: 0 }).top;
                    }
                    if (ls) {
                        ui.position.left = inst._convertpositionto("relative", { top: 0, left: l - inst.helperproportions.width }).left;
                    }
                    if (rs) {
                        ui.position.left = inst._convertpositionto("relative", { top: 0, left: r }).left;
                    }
                }

                first = (ts || bs || ls || rs);

                if (o.snapmode !== "outer") {
                    ts = math.abs(t - y1) <= d;
                    bs = math.abs(b - y2) <= d;
                    ls = math.abs(l - x1) <= d;
                    rs = math.abs(r - x2) <= d;
                    if (ts) {
                        ui.position.top = inst._convertpositionto("relative", { top: t, left: 0 }).top;
                    }
                    if (bs) {
                        ui.position.top = inst._convertpositionto("relative", { top: b - inst.helperproportions.height, left: 0 }).top;
                    }
                    if (ls) {
                        ui.position.left = inst._convertpositionto("relative", { top: 0, left: l }).left;
                    }
                    if (rs) {
                        ui.position.left = inst._convertpositionto("relative", { top: 0, left: r - inst.helperproportions.width }).left;
                    }
                }

                if (!inst.snapelements[i].snapping && (ts || bs || ls || rs || first)) {
                    (inst.options.snap.snap && inst.options.snap.snap.call(inst.element, event, $.extend(inst._uihash(), { snapitem: inst.snapelements[i].item })));
                }
                inst.snapelements[i].snapping = (ts || bs || ls || rs || first);

            }

        }
    });

    $.ui.plugin.add("draggable", "stack", {
        start: function( event, ui, instance ) {
            var min,
                o = instance.options,
                group = $.makearray($(o.stack)).sort(function(a, b) {
                    return (parseint($(a).css("zindex"), 10) || 0) - (parseint($(b).css("zindex"), 10) || 0);
                });

            if (!group.length) { return; }

            min = parseint($(group[0]).css("zindex"), 10) || 0;
            $(group).each(function(i) {
                $(this).css("zindex", min + i);
            });
            this.css("zindex", (min + group.length));
        }
    });

    $.ui.plugin.add("draggable", "zindex", {
        start: function( event, ui, instance ) {
            var t = $( ui.helper ),
                o = instance.options;

            if (t.css("zindex")) {
                o._zindex = t.css("zindex");
            }
            t.css("zindex", o.zindex);
        },
        stop: function( event, ui, instance ) {
            var o = instance.options;

            if (o._zindex) {
                $(ui.helper).css("zindex", o._zindex);
            }
        }
    });

    var draggable = $.ui.draggable;


    /*!
     * jquery ui resizable 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/resizable/
     */


    $.widget("ui.resizable", $.ui.mouse, {
        version: "1.11.2",
        widgeteventprefix: "resize",
        options: {
            alsoresize: false,
            animate: false,
            animateduration: "slow",
            animateeasing: "swing",
            aspectratio: false,
            autohide: false,
            containment: false,
            ghost: false,
            grid: false,
            handles: "e,s,se",
            helper: false,
            maxheight: null,
            maxwidth: null,
            minheight: 10,
            minwidth: 10,
            // see #7960
            zindex: 90,

            // callbacks
            resize: null,
            start: null,
            stop: null
        },

        _num: function( value ) {
            return parseint( value, 10 ) || 0;
        },

        _isnumber: function( value ) {
            return !isnan( parseint( value, 10 ) );
        },

        _hasscroll: function( el, a ) {

            if ( $( el ).css( "overflow" ) === "hidden") {
                return false;
            }

            var scroll = ( a && a === "left" ) ? "scrollleft" : "scrolltop",
                has = false;

            if ( el[ scroll ] > 0 ) {
                return true;
            }

            // todo: determine which cases actually cause this to happen
            // if the element doesn't have the scroll set, see if it's possible to
            // set the scroll
            el[ scroll ] = 1;
            has = ( el[ scroll ] > 0 );
            el[ scroll ] = 0;
            return has;
        },

        _create: function() {

            var n, i, handle, axis, hname,
                that = this,
                o = this.options;
            this.element.addclass("ui-resizable");

            $.extend(this, {
                _aspectratio: !!(o.aspectratio),
                aspectratio: o.aspectratio,
                originalelement: this.element,
                _proportionallyresizeelements: [],
                _helper: o.helper || o.ghost || o.animate ? o.helper || "ui-resizable-helper" : null
            });

            // wrap the element if it cannot hold child nodes
            if (this.element[0].nodename.match(/canvas|textarea|input|select|button|img/i)) {

                this.element.wrap(
                    $("<div class='ui-wrapper' style='overflow: hidden;'></div>").css({
                        position: this.element.css("position"),
                        width: this.element.outerwidth(),
                        height: this.element.outerheight(),
                        top: this.element.css("top"),
                        left: this.element.css("left")
                    })
                );

                this.element = this.element.parent().data(
                    "ui-resizable", this.element.resizable( "instance" )
                );

                this.elementiswrapper = true;

                this.element.css({
                    marginleft: this.originalelement.css("marginleft"),
                    margintop: this.originalelement.css("margintop"),
                    marginright: this.originalelement.css("marginright"),
                    marginbottom: this.originalelement.css("marginbottom")
                });
                this.originalelement.css({
                    marginleft: 0,
                    margintop: 0,
                    marginright: 0,
                    marginbottom: 0
                });
                // support: safari
                // prevent safari textarea resize
                this.originalresizestyle = this.originalelement.css("resize");
                this.originalelement.css("resize", "none");

                this._proportionallyresizeelements.push( this.originalelement.css({
                    position: "static",
                    zoom: 1,
                    display: "block"
                }) );

                // support: ie9
                // avoid ie jump (hard set the margin)
                this.originalelement.css({ margin: this.originalelement.css("margin") });

                this._proportionallyresize();
            }

            this.handles = o.handles ||
                ( !$(".ui-resizable-handle", this.element).length ?
                    "e,s,se" : {
                    n: ".ui-resizable-n",
                    e: ".ui-resizable-e",
                    s: ".ui-resizable-s",
                    w: ".ui-resizable-w",
                    se: ".ui-resizable-se",
                    sw: ".ui-resizable-sw",
                    ne: ".ui-resizable-ne",
                    nw: ".ui-resizable-nw"
                } );

            if (this.handles.constructor === string) {

                if ( this.handles === "all") {
                    this.handles = "n,e,s,w,se,sw,ne,nw";
                }

                n = this.handles.split(",");
                this.handles = {};

                for (i = 0; i < n.length; i++) {

                    handle = $.trim(n[i]);
                    hname = "ui-resizable-" + handle;
                    axis = $("<div class='ui-resizable-handle " + hname + "'></div>");

                    axis.css({ zindex: o.zindex });

                    // todo : what's going on here?
                    if ("se" === handle) {
                        axis.addclass("ui-icon ui-icon-gripsmall-diagonal-se");
                    }

                    this.handles[handle] = ".ui-resizable-" + handle;
                    this.element.append(axis);
                }

            }

            this._renderaxis = function(target) {

                var i, axis, padpos, padwrapper;

                target = target || this.element;

                for (i in this.handles) {

                    if (this.handles[i].constructor === string) {
                        this.handles[i] = this.element.children( this.handles[ i ] ).first().show();
                    }

                    if (this.elementiswrapper && this.originalelement[0].nodename.match(/textarea|input|select|button/i)) {

                        axis = $(this.handles[i], this.element);

                        padwrapper = /sw|ne|nw|se|n|s/.test(i) ? axis.outerheight() : axis.outerwidth();

                        padpos = [ "padding",
                            /ne|nw|n/.test(i) ? "top" :
                                /se|sw|s/.test(i) ? "bottom" :
                                    /^e$/.test(i) ? "right" : "left" ].join("");

                        target.css(padpos, padwrapper);

                        this._proportionallyresize();

                    }

                    // todo: what's that good for? there's not anything to be executed left
                    if (!$(this.handles[i]).length) {
                        continue;
                    }
                }
            };

            // todo: make renderaxis a prototype function
            this._renderaxis(this.element);

            this._handles = $(".ui-resizable-handle", this.element)
                .disableselection();

            this._handles.mouseover(function() {
                if (!that.resizing) {
                    if (this.classname) {
                        axis = this.classname.match(/ui-resizable-(se|sw|ne|nw|n|e|s|w)/i);
                    }
                    that.axis = axis && axis[1] ? axis[1] : "se";
                }
            });

            if (o.autohide) {
                this._handles.hide();
                $(this.element)
                    .addclass("ui-resizable-autohide")
                    .mouseenter(function() {
                        if (o.disabled) {
                            return;
                        }
                        $(this).removeclass("ui-resizable-autohide");
                        that._handles.show();
                    })
                    .mouseleave(function() {
                        if (o.disabled) {
                            return;
                        }
                        if (!that.resizing) {
                            $(this).addclass("ui-resizable-autohide");
                            that._handles.hide();
                        }
                    });
            }

            this._mouseinit();

        },

        _destroy: function() {

            this._mousedestroy();

            var wrapper,
                _destroy = function(exp) {
                    $(exp)
                        .removeclass("ui-resizable ui-resizable-disabled ui-resizable-resizing")
                        .removedata("resizable")
                        .removedata("ui-resizable")
                        .unbind(".resizable")
                        .find(".ui-resizable-handle")
                        .remove();
                };

            // todo: unwrap at same dom position
            if (this.elementiswrapper) {
                _destroy(this.element);
                wrapper = this.element;
                this.originalelement.css({
                    position: wrapper.css("position"),
                    width: wrapper.outerwidth(),
                    height: wrapper.outerheight(),
                    top: wrapper.css("top"),
                    left: wrapper.css("left")
                }).insertafter( wrapper );
                wrapper.remove();
            }

            this.originalelement.css("resize", this.originalresizestyle);
            _destroy(this.originalelement);

            return this;
        },

        _mousecapture: function(event) {
            var i, handle,
                capture = false;

            for (i in this.handles) {
                handle = $(this.handles[i])[0];
                if (handle === event.target || $.contains(handle, event.target)) {
                    capture = true;
                }
            }

            return !this.options.disabled && capture;
        },

        _mousestart: function(event) {

            var curleft, curtop, cursor,
                o = this.options,
                el = this.element;

            this.resizing = true;

            this._renderproxy();

            curleft = this._num(this.helper.css("left"));
            curtop = this._num(this.helper.css("top"));

            if (o.containment) {
                curleft += $(o.containment).scrollleft() || 0;
                curtop += $(o.containment).scrolltop() || 0;
            }

            this.offset = this.helper.offset();
            this.position = { left: curleft, top: curtop };

            this.size = this._helper ? {
                width: this.helper.width(),
                height: this.helper.height()
            } : {
                width: el.width(),
                height: el.height()
            };

            this.originalsize = this._helper ? {
                width: el.outerwidth(),
                height: el.outerheight()
            } : {
                width: el.width(),
                height: el.height()
            };

            this.sizediff = {
                width: el.outerwidth() - el.width(),
                height: el.outerheight() - el.height()
            };

            this.originalposition = { left: curleft, top: curtop };
            this.originalmouseposition = { left: event.pagex, top: event.pagey };

            this.aspectratio = (typeof o.aspectratio === "number") ?
                o.aspectratio :
                ((this.originalsize.width / this.originalsize.height) || 1);

            cursor = $(".ui-resizable-" + this.axis).css("cursor");
            $("body").css("cursor", cursor === "auto" ? this.axis + "-resize" : cursor);

            el.addclass("ui-resizable-resizing");
            this._propagate("start", event);
            return true;
        },

        _mousedrag: function(event) {

            var data, props,
                smp = this.originalmouseposition,
                a = this.axis,
                dx = (event.pagex - smp.left) || 0,
                dy = (event.pagey - smp.top) || 0,
                trigger = this._change[a];

            this._updateprevproperties();

            if (!trigger) {
                return false;
            }

            data = trigger.apply(this, [ event, dx, dy ]);

            this._updatevirtualboundaries(event.shiftkey);
            if (this._aspectratio || event.shiftkey) {
                data = this._updateratio(data, event);
            }

            data = this._respectsize(data, event);

            this._updatecache(data);

            this._propagate("resize", event);

            props = this._applychanges();

            if ( !this._helper && this._proportionallyresizeelements.length ) {
                this._proportionallyresize();
            }

            if ( !$.isemptyobject( props ) ) {
                this._updateprevproperties();
                this._trigger( "resize", event, this.ui() );
                this._applychanges();
            }

            return false;
        },

        _mousestop: function(event) {

            this.resizing = false;
            var pr, ista, soffseth, soffsetw, s, left, top,
                o = this.options, that = this;

            if (this._helper) {

                pr = this._proportionallyresizeelements;
                ista = pr.length && (/textarea/i).test(pr[0].nodename);
                soffseth = ista && this._hasscroll(pr[0], "left") ? 0 : that.sizediff.height;
                soffsetw = ista ? 0 : that.sizediff.width;

                s = {
                    width: (that.helper.width()  - soffsetw),
                    height: (that.helper.height() - soffseth)
                };
                left = (parseint(that.element.css("left"), 10) +
                    (that.position.left - that.originalposition.left)) || null;
                top = (parseint(that.element.css("top"), 10) +
                    (that.position.top - that.originalposition.top)) || null;

                if (!o.animate) {
                    this.element.css($.extend(s, { top: top, left: left }));
                }

                that.helper.height(that.size.height);
                that.helper.width(that.size.width);

                if (this._helper && !o.animate) {
                    this._proportionallyresize();
                }
            }

            $("body").css("cursor", "auto");

            this.element.removeclass("ui-resizable-resizing");

            this._propagate("stop", event);

            if (this._helper) {
                this.helper.remove();
            }

            return false;

        },

        _updateprevproperties: function() {
            this.prevposition = {
                top: this.position.top,
                left: this.position.left
            };
            this.prevsize = {
                width: this.size.width,
                height: this.size.height
            };
        },

        _applychanges: function() {
            var props = {};

            if ( this.position.top !== this.prevposition.top ) {
                props.top = this.position.top + "px";
            }
            if ( this.position.left !== this.prevposition.left ) {
                props.left = this.position.left + "px";
            }
            if ( this.size.width !== this.prevsize.width ) {
                props.width = this.size.width + "px";
            }
            if ( this.size.height !== this.prevsize.height ) {
                props.height = this.size.height + "px";
            }

            this.helper.css( props );

            return props;
        },

        _updatevirtualboundaries: function(forceaspectratio) {
            var pminwidth, pmaxwidth, pminheight, pmaxheight, b,
                o = this.options;

            b = {
                minwidth: this._isnumber(o.minwidth) ? o.minwidth : 0,
                maxwidth: this._isnumber(o.maxwidth) ? o.maxwidth : infinity,
                minheight: this._isnumber(o.minheight) ? o.minheight : 0,
                maxheight: this._isnumber(o.maxheight) ? o.maxheight : infinity
            };

            if (this._aspectratio || forceaspectratio) {
                pminwidth = b.minheight * this.aspectratio;
                pminheight = b.minwidth / this.aspectratio;
                pmaxwidth = b.maxheight * this.aspectratio;
                pmaxheight = b.maxwidth / this.aspectratio;

                if (pminwidth > b.minwidth) {
                    b.minwidth = pminwidth;
                }
                if (pminheight > b.minheight) {
                    b.minheight = pminheight;
                }
                if (pmaxwidth < b.maxwidth) {
                    b.maxwidth = pmaxwidth;
                }
                if (pmaxheight < b.maxheight) {
                    b.maxheight = pmaxheight;
                }
            }
            this._vboundaries = b;
        },

        _updatecache: function(data) {
            this.offset = this.helper.offset();
            if (this._isnumber(data.left)) {
                this.position.left = data.left;
            }
            if (this._isnumber(data.top)) {
                this.position.top = data.top;
            }
            if (this._isnumber(data.height)) {
                this.size.height = data.height;
            }
            if (this._isnumber(data.width)) {
                this.size.width = data.width;
            }
        },

        _updateratio: function( data ) {

            var cpos = this.position,
                csize = this.size,
                a = this.axis;

            if (this._isnumber(data.height)) {
                data.width = (data.height * this.aspectratio);
            } else if (this._isnumber(data.width)) {
                data.height = (data.width / this.aspectratio);
            }

            if (a === "sw") {
                data.left = cpos.left + (csize.width - data.width);
                data.top = null;
            }
            if (a === "nw") {
                data.top = cpos.top + (csize.height - data.height);
                data.left = cpos.left + (csize.width - data.width);
            }

            return data;
        },

        _respectsize: function( data ) {

            var o = this._vboundaries,
                a = this.axis,
                ismaxw = this._isnumber(data.width) && o.maxwidth && (o.maxwidth < data.width),
                ismaxh = this._isnumber(data.height) && o.maxheight && (o.maxheight < data.height),
                isminw = this._isnumber(data.width) && o.minwidth && (o.minwidth > data.width),
                isminh = this._isnumber(data.height) && o.minheight && (o.minheight > data.height),
                dw = this.originalposition.left + this.originalsize.width,
                dh = this.position.top + this.size.height,
                cw = /sw|nw|w/.test(a), ch = /nw|ne|n/.test(a);
            if (isminw) {
                data.width = o.minwidth;
            }
            if (isminh) {
                data.height = o.minheight;
            }
            if (ismaxw) {
                data.width = o.maxwidth;
            }
            if (ismaxh) {
                data.height = o.maxheight;
            }

            if (isminw && cw) {
                data.left = dw - o.minwidth;
            }
            if (ismaxw && cw) {
                data.left = dw - o.maxwidth;
            }
            if (isminh && ch) {
                data.top = dh - o.minheight;
            }
            if (ismaxh && ch) {
                data.top = dh - o.maxheight;
            }

            // fixing jump error on top/left - bug #2330
            if (!data.width && !data.height && !data.left && data.top) {
                data.top = null;
            } else if (!data.width && !data.height && !data.top && data.left) {
                data.left = null;
            }

            return data;
        },

        _getpaddingplusborderdimensions: function( element ) {
            var i = 0,
                widths = [],
                borders = [
                    element.css( "bordertopwidth" ),
                    element.css( "borderrightwidth" ),
                    element.css( "borderbottomwidth" ),
                    element.css( "borderleftwidth" )
                ],
                paddings = [
                    element.css( "paddingtop" ),
                    element.css( "paddingright" ),
                    element.css( "paddingbottom" ),
                    element.css( "paddingleft" )
                ];

            for ( ; i < 4; i++ ) {
                widths[ i ] = ( parseint( borders[ i ], 10 ) || 0 );
                widths[ i ] += ( parseint( paddings[ i ], 10 ) || 0 );
            }

            return {
                height: widths[ 0 ] + widths[ 2 ],
                width: widths[ 1 ] + widths[ 3 ]
            };
        },

        _proportionallyresize: function() {

            if (!this._proportionallyresizeelements.length) {
                return;
            }

            var prel,
                i = 0,
                element = this.helper || this.element;

            for ( ; i < this._proportionallyresizeelements.length; i++) {

                prel = this._proportionallyresizeelements[i];

                // todo: seems like a bug to cache this.outerdimensions
                // considering that we are in a loop.
                if (!this.outerdimensions) {
                    this.outerdimensions = this._getpaddingplusborderdimensions( prel );
                }

                prel.css({
                    height: (element.height() - this.outerdimensions.height) || 0,
                    width: (element.width() - this.outerdimensions.width) || 0
                });

            }

        },

        _renderproxy: function() {

            var el = this.element, o = this.options;
            this.elementoffset = el.offset();

            if (this._helper) {

                this.helper = this.helper || $("<div style='overflow:hidden;'></div>");

                this.helper.addclass(this._helper).css({
                    width: this.element.outerwidth() - 1,
                    height: this.element.outerheight() - 1,
                    position: "absolute",
                    left: this.elementoffset.left + "px",
                    top: this.elementoffset.top + "px",
                    zindex: ++o.zindex //todo: don't modify option
                });

                this.helper
                    .appendto("body")
                    .disableselection();

            } else {
                this.helper = this.element;
            }

        },

        _change: {
            e: function(event, dx) {
                return { width: this.originalsize.width + dx };
            },
            w: function(event, dx) {
                var cs = this.originalsize, sp = this.originalposition;
                return { left: sp.left + dx, width: cs.width - dx };
            },
            n: function(event, dx, dy) {
                var cs = this.originalsize, sp = this.originalposition;
                return { top: sp.top + dy, height: cs.height - dy };
            },
            s: function(event, dx, dy) {
                return { height: this.originalsize.height + dy };
            },
            se: function(event, dx, dy) {
                return $.extend(this._change.s.apply(this, arguments),
                    this._change.e.apply(this, [ event, dx, dy ]));
            },
            sw: function(event, dx, dy) {
                return $.extend(this._change.s.apply(this, arguments),
                    this._change.w.apply(this, [ event, dx, dy ]));
            },
            ne: function(event, dx, dy) {
                return $.extend(this._change.n.apply(this, arguments),
                    this._change.e.apply(this, [ event, dx, dy ]));
            },
            nw: function(event, dx, dy) {
                return $.extend(this._change.n.apply(this, arguments),
                    this._change.w.apply(this, [ event, dx, dy ]));
            }
        },

        _propagate: function(n, event) {
            $.ui.plugin.call(this, n, [ event, this.ui() ]);
            (n !== "resize" && this._trigger(n, event, this.ui()));
        },

        plugins: {},

        ui: function() {
            return {
                originalelement: this.originalelement,
                element: this.element,
                helper: this.helper,
                position: this.position,
                size: this.size,
                originalsize: this.originalsize,
                originalposition: this.originalposition
            };
        }

    });

    /*
     * resizable extensions
     */

    $.ui.plugin.add("resizable", "animate", {

        stop: function( event ) {
            var that = $(this).resizable( "instance" ),
                o = that.options,
                pr = that._proportionallyresizeelements,
                ista = pr.length && (/textarea/i).test(pr[0].nodename),
                soffseth = ista && that._hasscroll(pr[0], "left") ? 0 : that.sizediff.height,
                soffsetw = ista ? 0 : that.sizediff.width,
                style = { width: (that.size.width - soffsetw), height: (that.size.height - soffseth) },
                left = (parseint(that.element.css("left"), 10) +
                    (that.position.left - that.originalposition.left)) || null,
                top = (parseint(that.element.css("top"), 10) +
                    (that.position.top - that.originalposition.top)) || null;

            that.element.animate(
                $.extend(style, top && left ? { top: top, left: left } : {}), {
                    duration: o.animateduration,
                    easing: o.animateeasing,
                    step: function() {

                        var data = {
                            width: parseint(that.element.css("width"), 10),
                            height: parseint(that.element.css("height"), 10),
                            top: parseint(that.element.css("top"), 10),
                            left: parseint(that.element.css("left"), 10)
                        };

                        if (pr && pr.length) {
                            $(pr[0]).css({ width: data.width, height: data.height });
                        }

                        // propagating resize, and updating values for each animation step
                        that._updatecache(data);
                        that._propagate("resize", event);

                    }
                }
            );
        }

    });

    $.ui.plugin.add( "resizable", "containment", {

        start: function() {
            var element, p, co, ch, cw, width, height,
                that = $( this ).resizable( "instance" ),
                o = that.options,
                el = that.element,
                oc = o.containment,
                ce = ( oc instanceof $ ) ? oc.get( 0 ) : ( /parent/.test( oc ) ) ? el.parent().get( 0 ) : oc;

            if ( !ce ) {
                return;
            }

            that.containerelement = $( ce );

            if ( /document/.test( oc ) || oc === document ) {
                that.containeroffset = {
                    left: 0,
                    top: 0
                };
                that.containerposition = {
                    left: 0,
                    top: 0
                };

                that.parentdata = {
                    element: $( document ),
                    left: 0,
                    top: 0,
                    width: $( document ).width(),
                    height: $( document ).height() || document.body.parentnode.scrollheight
                };
            } else {
                element = $( ce );
                p = [];
                $([ "top", "right", "left", "bottom" ]).each(function( i, name ) {
                    p[ i ] = that._num( element.css( "padding" + name ) );
                });

                that.containeroffset = element.offset();
                that.containerposition = element.position();
                that.containersize = {
                    height: ( element.innerheight() - p[ 3 ] ),
                    width: ( element.innerwidth() - p[ 1 ] )
                };

                co = that.containeroffset;
                ch = that.containersize.height;
                cw = that.containersize.width;
                width = ( that._hasscroll ( ce, "left" ) ? ce.scrollwidth : cw );
                height = ( that._hasscroll ( ce ) ? ce.scrollheight : ch ) ;

                that.parentdata = {
                    element: ce,
                    left: co.left,
                    top: co.top,
                    width: width,
                    height: height
                };
            }
        },

        resize: function( event ) {
            var woset, hoset, isparent, isoffsetrelative,
                that = $( this ).resizable( "instance" ),
                o = that.options,
                co = that.containeroffset,
                cp = that.position,
                pratio = that._aspectratio || event.shiftkey,
                cop = {
                    top: 0,
                    left: 0
                },
                ce = that.containerelement,
                continueresize = true;

            if ( ce[ 0 ] !== document && ( /static/ ).test( ce.css( "position" ) ) ) {
                cop = co;
            }

            if ( cp.left < ( that._helper ? co.left : 0 ) ) {
                that.size.width = that.size.width +
                    ( that._helper ?
                        ( that.position.left - co.left ) :
                        ( that.position.left - cop.left ) );

                if ( pratio ) {
                    that.size.height = that.size.width / that.aspectratio;
                    continueresize = false;
                }
                that.position.left = o.helper ? co.left : 0;
            }

            if ( cp.top < ( that._helper ? co.top : 0 ) ) {
                that.size.height = that.size.height +
                    ( that._helper ?
                        ( that.position.top - co.top ) :
                        that.position.top );

                if ( pratio ) {
                    that.size.width = that.size.height * that.aspectratio;
                    continueresize = false;
                }
                that.position.top = that._helper ? co.top : 0;
            }

            isparent = that.containerelement.get( 0 ) === that.element.parent().get( 0 );
            isoffsetrelative = /relative|absolute/.test( that.containerelement.css( "position" ) );

            if ( isparent && isoffsetrelative ) {
                that.offset.left = that.parentdata.left + that.position.left;
                that.offset.top = that.parentdata.top + that.position.top;
            } else {
                that.offset.left = that.element.offset().left;
                that.offset.top = that.element.offset().top;
            }

            woset = math.abs( that.sizediff.width +
                (that._helper ?
                    that.offset.left - cop.left :
                    (that.offset.left - co.left)) );

            hoset = math.abs( that.sizediff.height +
                (that._helper ?
                    that.offset.top - cop.top :
                    (that.offset.top - co.top)) );

            if ( woset + that.size.width >= that.parentdata.width ) {
                that.size.width = that.parentdata.width - woset;
                if ( pratio ) {
                    that.size.height = that.size.width / that.aspectratio;
                    continueresize = false;
                }
            }

            if ( hoset + that.size.height >= that.parentdata.height ) {
                that.size.height = that.parentdata.height - hoset;
                if ( pratio ) {
                    that.size.width = that.size.height * that.aspectratio;
                    continueresize = false;
                }
            }

            if ( !continueresize ){
                that.position.left = that.prevposition.left;
                that.position.top = that.prevposition.top;
                that.size.width = that.prevsize.width;
                that.size.height = that.prevsize.height;
            }
        },

        stop: function() {
            var that = $( this ).resizable( "instance" ),
                o = that.options,
                co = that.containeroffset,
                cop = that.containerposition,
                ce = that.containerelement,
                helper = $( that.helper ),
                ho = helper.offset(),
                w = helper.outerwidth() - that.sizediff.width,
                h = helper.outerheight() - that.sizediff.height;

            if ( that._helper && !o.animate && ( /relative/ ).test( ce.css( "position" ) ) ) {
                $( this ).css({
                    left: ho.left - cop.left - co.left,
                    width: w,
                    height: h
                });
            }

            if ( that._helper && !o.animate && ( /static/ ).test( ce.css( "position" ) ) ) {
                $( this ).css({
                    left: ho.left - cop.left - co.left,
                    width: w,
                    height: h
                });
            }
        }
    });

    $.ui.plugin.add("resizable", "alsoresize", {

        start: function() {
            var that = $(this).resizable( "instance" ),
                o = that.options,
                _store = function(exp) {
                    $(exp).each(function() {
                        var el = $(this);
                        el.data("ui-resizable-alsoresize", {
                            width: parseint(el.width(), 10), height: parseint(el.height(), 10),
                            left: parseint(el.css("left"), 10), top: parseint(el.css("top"), 10)
                        });
                    });
                };

            if (typeof(o.alsoresize) === "object" && !o.alsoresize.parentnode) {
                if (o.alsoresize.length) {
                    o.alsoresize = o.alsoresize[0];
                    _store(o.alsoresize);
                } else {
                    $.each(o.alsoresize, function(exp) {
                        _store(exp);
                    });
                }
            } else {
                _store(o.alsoresize);
            }
        },

        resize: function(event, ui) {
            var that = $(this).resizable( "instance" ),
                o = that.options,
                os = that.originalsize,
                op = that.originalposition,
                delta = {
                    height: (that.size.height - os.height) || 0,
                    width: (that.size.width - os.width) || 0,
                    top: (that.position.top - op.top) || 0,
                    left: (that.position.left - op.left) || 0
                },

                _alsoresize = function(exp, c) {
                    $(exp).each(function() {
                        var el = $(this), start = $(this).data("ui-resizable-alsoresize"), style = {},
                            css = c && c.length ?
                                c :
                                el.parents(ui.originalelement[0]).length ?
                                    [ "width", "height" ] :
                                    [ "width", "height", "top", "left" ];

                        $.each(css, function(i, prop) {
                            var sum = (start[prop] || 0) + (delta[prop] || 0);
                            if (sum && sum >= 0) {
                                style[prop] = sum || null;
                            }
                        });

                        el.css(style);
                    });
                };

            if (typeof(o.alsoresize) === "object" && !o.alsoresize.nodetype) {
                $.each(o.alsoresize, function(exp, c) {
                    _alsoresize(exp, c);
                });
            } else {
                _alsoresize(o.alsoresize);
            }
        },

        stop: function() {
            $(this).removedata("resizable-alsoresize");
        }
    });

    $.ui.plugin.add("resizable", "ghost", {

        start: function() {

            var that = $(this).resizable( "instance" ), o = that.options, cs = that.size;

            that.ghost = that.originalelement.clone();
            that.ghost
                .css({
                    opacity: 0.25,
                    display: "block",
                    position: "relative",
                    height: cs.height,
                    width: cs.width,
                    margin: 0,
                    left: 0,
                    top: 0
                })
                .addclass("ui-resizable-ghost")
                .addclass(typeof o.ghost === "string" ? o.ghost : "");

            that.ghost.appendto(that.helper);

        },

        resize: function() {
            var that = $(this).resizable( "instance" );
            if (that.ghost) {
                that.ghost.css({
                    position: "relative",
                    height: that.size.height,
                    width: that.size.width
                });
            }
        },

        stop: function() {
            var that = $(this).resizable( "instance" );
            if (that.ghost && that.helper) {
                that.helper.get(0).removechild(that.ghost.get(0));
            }
        }

    });

    $.ui.plugin.add("resizable", "grid", {

        resize: function() {
            var outerdimensions,
                that = $(this).resizable( "instance" ),
                o = that.options,
                cs = that.size,
                os = that.originalsize,
                op = that.originalposition,
                a = that.axis,
                grid = typeof o.grid === "number" ? [ o.grid, o.grid ] : o.grid,
                gridx = (grid[0] || 1),
                gridy = (grid[1] || 1),
                ox = math.round((cs.width - os.width) / gridx) * gridx,
                oy = math.round((cs.height - os.height) / gridy) * gridy,
                newwidth = os.width + ox,
                newheight = os.height + oy,
                ismaxwidth = o.maxwidth && (o.maxwidth < newwidth),
                ismaxheight = o.maxheight && (o.maxheight < newheight),
                isminwidth = o.minwidth && (o.minwidth > newwidth),
                isminheight = o.minheight && (o.minheight > newheight);

            o.grid = grid;

            if (isminwidth) {
                newwidth += gridx;
            }
            if (isminheight) {
                newheight += gridy;
            }
            if (ismaxwidth) {
                newwidth -= gridx;
            }
            if (ismaxheight) {
                newheight -= gridy;
            }

            if (/^(se|s|e)$/.test(a)) {
                that.size.width = newwidth;
                that.size.height = newheight;
            } else if (/^(ne)$/.test(a)) {
                that.size.width = newwidth;
                that.size.height = newheight;
                that.position.top = op.top - oy;
            } else if (/^(sw)$/.test(a)) {
                that.size.width = newwidth;
                that.size.height = newheight;
                that.position.left = op.left - ox;
            } else {
                if ( newheight - gridy <= 0 || newwidth - gridx <= 0) {
                    outerdimensions = that._getpaddingplusborderdimensions( this );
                }

                if ( newheight - gridy > 0 ) {
                    that.size.height = newheight;
                    that.position.top = op.top - oy;
                } else {
                    newheight = gridy - outerdimensions.height;
                    that.size.height = newheight;
                    that.position.top = op.top + os.height - newheight;
                }
                if ( newwidth - gridx > 0 ) {
                    that.size.width = newwidth;
                    that.position.left = op.left - ox;
                } else {
                    newwidth = gridy - outerdimensions.height;
                    that.size.width = newwidth;
                    that.position.left = op.left + os.width - newwidth;
                }
            }
        }

    });

    var resizable = $.ui.resizable;


    /*!
     * jquery ui dialog 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/dialog/
     */


    var dialog = $.widget( "ui.dialog", {
        version: "1.11.2",
        options: {
            appendto: "body",
            autoopen: true,
            buttons: [],
            closeonescape: true,
            closetext: "close",
            dialogclass: "",
            draggable: true,
            hide: null,
            height: "auto",
            maxheight: null,
            maxwidth: null,
            minheight: 150,
            minwidth: 150,
            modal: false,
            position: {
                my: "center",
                at: "center",
                of: window,
                collision: "fit",
                // ensure the titlebar is always visible
                using: function( pos ) {
                    var topoffset = $( this ).css( pos ).offset().top;
                    if ( topoffset < 0 ) {
                        $( this ).css( "top", pos.top - topoffset );
                    }
                }
            },
            resizable: true,
            show: null,
            title: null,
            width: 300,

            // callbacks
            beforeclose: null,
            close: null,
            drag: null,
            dragstart: null,
            dragstop: null,
            focus: null,
            open: null,
            resize: null,
            resizestart: null,
            resizestop: null
        },

        sizerelatedoptions: {
            buttons: true,
            height: true,
            maxheight: true,
            maxwidth: true,
            minheight: true,
            minwidth: true,
            width: true
        },

        resizablerelatedoptions: {
            maxheight: true,
            maxwidth: true,
            minheight: true,
            minwidth: true
        },

        _create: function() {
            this.originalcss = {
                display: this.element[ 0 ].style.display,
                width: this.element[ 0 ].style.width,
                minheight: this.element[ 0 ].style.minheight,
                maxheight: this.element[ 0 ].style.maxheight,
                height: this.element[ 0 ].style.height
            };
            this.originalposition = {
                parent: this.element.parent(),
                index: this.element.parent().children().index( this.element )
            };
            this.originaltitle = this.element.attr( "title" );
            this.options.title = this.options.title || this.originaltitle;

            this._createwrapper();

            this.element
                .show()
                .removeattr( "title" )
                .addclass( "ui-dialog-content ui-widget-content" )
                .appendto( this.uidialog );

            this._createtitlebar();
            this._createbuttonpane();

            if ( this.options.draggable && $.fn.draggable ) {
                this._makedraggable();
            }
            if ( this.options.resizable && $.fn.resizable ) {
                this._makeresizable();
            }

            this._isopen = false;

            this._trackfocus();
        },

        _init: function() {
            if ( this.options.autoopen ) {
                this.open();
            }
        },

        _appendto: function() {
            var element = this.options.appendto;
            if ( element && (element.jquery || element.nodetype) ) {
                return $( element );
            }
            return this.document.find( element || "body" ).eq( 0 );
        },

        _destroy: function() {
            var next,
                originalposition = this.originalposition;

            this._destroyoverlay();

            this.element
                .removeuniqueid()
                .removeclass( "ui-dialog-content ui-widget-content" )
                .css( this.originalcss )
                // without detaching first, the following becomes really slow
                .detach();

            this.uidialog.stop( true, true ).remove();

            if ( this.originaltitle ) {
                this.element.attr( "title", this.originaltitle );
            }

            next = originalposition.parent.children().eq( originalposition.index );
            // don't try to place the dialog next to itself (#8613)
            if ( next.length && next[ 0 ] !== this.element[ 0 ] ) {
                next.before( this.element );
            } else {
                originalposition.parent.append( this.element );
            }
        },

        widget: function() {
            return this.uidialog;
        },

        disable: $.noop,
        enable: $.noop,

        close: function( event ) {
            var activeelement,
                that = this;

            if ( !this._isopen || this._trigger( "beforeclose", event ) === false ) {
                return;
            }

            this._isopen = false;
            this._focusedelement = null;
            this._destroyoverlay();
            this._untrackinstance();

            if ( !this.opener.filter( ":focusable" ).focus().length ) {

                // support: ie9
                // ie9 throws an "unspecified error" accessing document.activeelement from an <iframe>
                try {
                    activeelement = this.document[ 0 ].activeelement;

                    // support: ie9, ie10
                    // if the <body> is blurred, ie will switch windows, see #4520
                    if ( activeelement && activeelement.nodename.tolowercase() !== "body" ) {

                        // hiding a focused element doesn't trigger blur in webkit
                        // so in case we have nothing to focus on, explicitly blur the active element
                        // https://bugs.webkit.org/show_bug.cgi?id=47182
                        $( activeelement ).blur();
                    }
                } catch ( error ) {}
            }

            this._hide( this.uidialog, this.options.hide, function() {
                that._trigger( "close", event );
            });
        },

        isopen: function() {
            return this._isopen;
        },

        movetotop: function() {
            this._movetotop();
        },

        _movetotop: function( event, silent ) {
            var moved = false,
                zindicies = this.uidialog.siblings( ".ui-front:visible" ).map(function() {
                    return +$( this ).css( "z-index" );
                }).get(),
                zindexmax = math.max.apply( null, zindicies );

            if ( zindexmax >= +this.uidialog.css( "z-index" ) ) {
                this.uidialog.css( "z-index", zindexmax + 1 );
                moved = true;
            }

            if ( moved && !silent ) {
                this._trigger( "focus", event );
            }
            return moved;
        },

        open: function() {
            var that = this;
            if ( this._isopen ) {
                if ( this._movetotop() ) {
                    this._focustabbable();
                }
                return;
            }

            this._isopen = true;
            this.opener = $( this.document[ 0 ].activeelement );

            this._size();
            this._position();
            this._createoverlay();
            this._movetotop( null, true );

            // ensure the overlay is moved to the top with the dialog, but only when
            // opening. the overlay shouldn't move after the dialog is open so that
            // modeless dialogs opened after the modal dialog stack properly.
            if ( this.overlay ) {
                this.overlay.css( "z-index", this.uidialog.css( "z-index" ) - 1 );
            }

            this._show( this.uidialog, this.options.show, function() {
                that._focustabbable();
                that._trigger( "focus" );
            });

            // track the dialog immediately upon openening in case a focus event
            // somehow occurs outside of the dialog before an element inside the
            // dialog is focused (#10152)
            this._makefocustarget();

            this._trigger( "open" );
        },

        _focustabbable: function() {
            // set focus to the first match:
            // 1. an element that was focused previously
            // 2. first element inside the dialog matching [autofocus]
            // 3. tabbable element inside the content element
            // 4. tabbable element inside the buttonpane
            // 5. the close button
            // 6. the dialog itself
            var hasfocus = this._focusedelement;
            if ( !hasfocus ) {
                hasfocus = this.element.find( "[autofocus]" );
            }
            if ( !hasfocus.length ) {
                hasfocus = this.element.find( ":tabbable" );
            }
            if ( !hasfocus.length ) {
                hasfocus = this.uidialogbuttonpane.find( ":tabbable" );
            }
            if ( !hasfocus.length ) {
                hasfocus = this.uidialogtitlebarclose.filter( ":tabbable" );
            }
            if ( !hasfocus.length ) {
                hasfocus = this.uidialog;
            }
            hasfocus.eq( 0 ).focus();
        },

        _keepfocus: function( event ) {
            function checkfocus() {
                var activeelement = this.document[0].activeelement,
                    isactive = this.uidialog[0] === activeelement ||
                        $.contains( this.uidialog[0], activeelement );
                if ( !isactive ) {
                    this._focustabbable();
                }
            }
            event.preventdefault();
            checkfocus.call( this );
            // support: ie
            // ie <= 8 doesn't prevent moving focus even with event.preventdefault()
            // so we check again later
            this._delay( checkfocus );
        },

        _createwrapper: function() {
            this.uidialog = $("<div>")
                .addclass( "ui-dialog ui-widget ui-widget-content ui-corner-all ui-front " +
                    this.options.dialogclass )
                .hide()
                .attr({
                    // setting tabindex makes the div focusable
                    tabindex: -1,
                    role: "dialog"
                })
                .appendto( this._appendto() );

            this._on( this.uidialog, {
                keydown: function( event ) {
                    if ( this.options.closeonescape && !event.isdefaultprevented() && event.keycode &&
                        event.keycode === $.ui.keycode.escape ) {
                        event.preventdefault();
                        this.close( event );
                        return;
                    }

                    // prevent tabbing out of dialogs
                    if ( event.keycode !== $.ui.keycode.tab || event.isdefaultprevented() ) {
                        return;
                    }
                    var tabbables = this.uidialog.find( ":tabbable" ),
                        first = tabbables.filter( ":first" ),
                        last = tabbables.filter( ":last" );

                    if ( ( event.target === last[0] || event.target === this.uidialog[0] ) && !event.shiftkey ) {
                        this._delay(function() {
                            first.focus();
                        });
                        event.preventdefault();
                    } else if ( ( event.target === first[0] || event.target === this.uidialog[0] ) && event.shiftkey ) {
                        this._delay(function() {
                            last.focus();
                        });
                        event.preventdefault();
                    }
                },
                mousedown: function( event ) {
                    if ( this._movetotop( event ) ) {
                        this._focustabbable();
                    }
                }
            });

            // we assume that any existing aria-describedby attribute means
            // that the dialog content is marked up properly
            // otherwise we brute force the content as the description
            if ( !this.element.find( "[aria-describedby]" ).length ) {
                this.uidialog.attr({
                    "aria-describedby": this.element.uniqueid().attr( "id" )
                });
            }
        },

        _createtitlebar: function() {
            var uidialogtitle;

            this.uidialogtitlebar = $( "<div>" )
                .addclass( "ui-dialog-titlebar ui-widget-header ui-corner-all ui-helper-clearfix" )
                .prependto( this.uidialog );
            this._on( this.uidialogtitlebar, {
                mousedown: function( event ) {
                    // don't prevent click on close button (#8838)
                    // focusing a dialog that is partially scrolled out of view
                    // causes the browser to scroll it into view, preventing the click event
                    if ( !$( event.target ).closest( ".ui-dialog-titlebar-close" ) ) {
                        // dialog isn't getting focus when dragging (#8063)
                        this.uidialog.focus();
                    }
                }
            });

            // support: ie
            // use type="button" to prevent enter keypresses in textboxes from closing the
            // dialog in ie (#9312)
            this.uidialogtitlebarclose = $( "<button type='button'></button>" )
                .button({
                    label: this.options.closetext,
                    icons: {
                        primary: "ui-icon-closethick"
                    },
                    text: false
                })
                .addclass( "ui-dialog-titlebar-close" )
                .appendto( this.uidialogtitlebar );
            this._on( this.uidialogtitlebarclose, {
                click: function( event ) {
                    event.preventdefault();
                    this.close( event );
                }
            });

            uidialogtitle = $( "<span>" )
                .uniqueid()
                .addclass( "ui-dialog-title" )
                .prependto( this.uidialogtitlebar );
            this._title( uidialogtitle );

            this.uidialog.attr({
                "aria-labelledby": uidialogtitle.attr( "id" )
            });
        },

        _title: function( title ) {
            if ( !this.options.title ) {
                title.html( "&#160;" );
            }
            title.text( this.options.title );
        },

        _createbuttonpane: function() {
            this.uidialogbuttonpane = $( "<div>" )
                .addclass( "ui-dialog-buttonpane ui-widget-content ui-helper-clearfix" );

            this.uibuttonset = $( "<div>" )
                .addclass( "ui-dialog-buttonset" )
                .appendto( this.uidialogbuttonpane );

            this._createbuttons();
        },

        _createbuttons: function() {
            var that = this,
                buttons = this.options.buttons;

            // if we already have a button pane, remove it
            this.uidialogbuttonpane.remove();
            this.uibuttonset.empty();

            if ( $.isemptyobject( buttons ) || ($.isarray( buttons ) && !buttons.length) ) {
                this.uidialog.removeclass( "ui-dialog-buttons" );
                return;
            }

            $.each( buttons, function( name, props ) {
                var click, buttonoptions;
                props = $.isfunction( props ) ?
                { click: props, text: name } :
                    props;
                // default to a non-submitting button
                props = $.extend( { type: "button" }, props );
                // change the context for the click callback to be the main element
                click = props.click;
                props.click = function() {
                    click.apply( that.element[ 0 ], arguments );
                };
                buttonoptions = {
                    icons: props.icons,
                    text: props.showtext
                };
                delete props.icons;
                delete props.showtext;
                $( "<button></button>", props )
                    .button( buttonoptions )
                    .appendto( that.uibuttonset );
            });
            this.uidialog.addclass( "ui-dialog-buttons" );
            this.uidialogbuttonpane.appendto( this.uidialog );
        },

        _makedraggable: function() {
            var that = this,
                options = this.options;

            function filteredui( ui ) {
                return {
                    position: ui.position,
                    offset: ui.offset
                };
            }

            this.uidialog.draggable({
                cancel: ".ui-dialog-content, .ui-dialog-titlebar-close",
                handle: ".ui-dialog-titlebar",
                containment: "document",
                start: function( event, ui ) {
                    $( this ).addclass( "ui-dialog-dragging" );
                    that._blockframes();
                    that._trigger( "dragstart", event, filteredui( ui ) );
                },
                drag: function( event, ui ) {
                    that._trigger( "drag", event, filteredui( ui ) );
                },
                stop: function( event, ui ) {
                    var left = ui.offset.left - that.document.scrollleft(),
                        top = ui.offset.top - that.document.scrolltop();

                    options.position = {
                        my: "left top",
                        at: "left" + (left >= 0 ? "+" : "") + left + " " +
                            "top" + (top >= 0 ? "+" : "") + top,
                        of: that.window
                    };
                    $( this ).removeclass( "ui-dialog-dragging" );
                    that._unblockframes();
                    that._trigger( "dragstop", event, filteredui( ui ) );
                }
            });
        },

        _makeresizable: function() {
            var that = this,
                options = this.options,
                handles = options.resizable,
            // .ui-resizable has position: relative defined in the stylesheet
            // but dialogs have to use absolute or fixed positioning
                position = this.uidialog.css("position"),
                resizehandles = typeof handles === "string" ?
                    handles	:
                    "n,e,s,w,se,sw,ne,nw";

            function filteredui( ui ) {
                return {
                    originalposition: ui.originalposition,
                    originalsize: ui.originalsize,
                    position: ui.position,
                    size: ui.size
                };
            }

            this.uidialog.resizable({
                cancel: ".ui-dialog-content",
                containment: "document",
                alsoresize: this.element,
                maxwidth: options.maxwidth,
                maxheight: options.maxheight,
                minwidth: options.minwidth,
                minheight: this._minheight(),
                handles: resizehandles,
                start: function( event, ui ) {
                    $( this ).addclass( "ui-dialog-resizing" );
                    that._blockframes();
                    that._trigger( "resizestart", event, filteredui( ui ) );
                },
                resize: function( event, ui ) {
                    that._trigger( "resize", event, filteredui( ui ) );
                },
                stop: function( event, ui ) {
                    var offset = that.uidialog.offset(),
                        left = offset.left - that.document.scrollleft(),
                        top = offset.top - that.document.scrolltop();

                    options.height = that.uidialog.height();
                    options.width = that.uidialog.width();
                    options.position = {
                        my: "left top",
                        at: "left" + (left >= 0 ? "+" : "") + left + " " +
                            "top" + (top >= 0 ? "+" : "") + top,
                        of: that.window
                    };
                    $( this ).removeclass( "ui-dialog-resizing" );
                    that._unblockframes();
                    that._trigger( "resizestop", event, filteredui( ui ) );
                }
            })
                .css( "position", position );
        },

        _trackfocus: function() {
            this._on( this.widget(), {
                focusin: function( event ) {
                    this._makefocustarget();
                    this._focusedelement = $( event.target );
                }
            });
        },

        _makefocustarget: function() {
            this._untrackinstance();
            this._trackinginstances().unshift( this );
        },

        _untrackinstance: function() {
            var instances = this._trackinginstances(),
                exists = $.inarray( this, instances );
            if ( exists !== -1 ) {
                instances.splice( exists, 1 );
            }
        },

        _trackinginstances: function() {
            var instances = this.document.data( "ui-dialog-instances" );
            if ( !instances ) {
                instances = [];
                this.document.data( "ui-dialog-instances", instances );
            }
            return instances;
        },

        _minheight: function() {
            var options = this.options;

            return options.height === "auto" ?
                options.minheight :
                math.min( options.minheight, options.height );
        },

        _position: function() {
            // need to show the dialog to get the actual offset in the position plugin
            var isvisible = this.uidialog.is( ":visible" );
            if ( !isvisible ) {
                this.uidialog.show();
            }
            this.uidialog.position( this.options.position );
            if ( !isvisible ) {
                this.uidialog.hide();
            }
        },

        _setoptions: function( options ) {
            var that = this,
                resize = false,
                resizableoptions = {};

            $.each( options, function( key, value ) {
                that._setoption( key, value );

                if ( key in that.sizerelatedoptions ) {
                    resize = true;
                }
                if ( key in that.resizablerelatedoptions ) {
                    resizableoptions[ key ] = value;
                }
            });

            if ( resize ) {
                this._size();
                this._position();
            }
            if ( this.uidialog.is( ":data(ui-resizable)" ) ) {
                this.uidialog.resizable( "option", resizableoptions );
            }
        },

        _setoption: function( key, value ) {
            var isdraggable, isresizable,
                uidialog = this.uidialog;

            if ( key === "dialogclass" ) {
                uidialog
                    .removeclass( this.options.dialogclass )
                    .addclass( value );
            }

            if ( key === "disabled" ) {
                return;
            }

            this._super( key, value );

            if ( key === "appendto" ) {
                this.uidialog.appendto( this._appendto() );
            }

            if ( key === "buttons" ) {
                this._createbuttons();
            }

            if ( key === "closetext" ) {
                this.uidialogtitlebarclose.button({
                    // ensure that we always pass a string
                    label: "" + value
                });
            }

            if ( key === "draggable" ) {
                isdraggable = uidialog.is( ":data(ui-draggable)" );
                if ( isdraggable && !value ) {
                    uidialog.draggable( "destroy" );
                }

                if ( !isdraggable && value ) {
                    this._makedraggable();
                }
            }

            if ( key === "position" ) {
                this._position();
            }

            if ( key === "resizable" ) {
                // currently resizable, becoming non-resizable
                isresizable = uidialog.is( ":data(ui-resizable)" );
                if ( isresizable && !value ) {
                    uidialog.resizable( "destroy" );
                }

                // currently resizable, changing handles
                if ( isresizable && typeof value === "string" ) {
                    uidialog.resizable( "option", "handles", value );
                }

                // currently non-resizable, becoming resizable
                if ( !isresizable && value !== false ) {
                    this._makeresizable();
                }
            }

            if ( key === "title" ) {
                this._title( this.uidialogtitlebar.find( ".ui-dialog-title" ) );
            }
        },

        _size: function() {
            // if the user has resized the dialog, the .ui-dialog and .ui-dialog-content
            // divs will both have width and height set, so we need to reset them
            var noncontentheight, mincontentheight, maxcontentheight,
                options = this.options;

            // reset content sizing
            this.element.show().css({
                width: "auto",
                minheight: 0,
                maxheight: "none",
                height: 0
            });

            if ( options.minwidth > options.width ) {
                options.width = options.minwidth;
            }

            // reset wrapper sizing
            // determine the height of all the non-content elements
            noncontentheight = this.uidialog.css({
                height: "auto",
                width: options.width
            })
                .outerheight();
            mincontentheight = math.max( 0, options.minheight - noncontentheight );
            maxcontentheight = typeof options.maxheight === "number" ?
                math.max( 0, options.maxheight - noncontentheight ) :
                "none";

            if ( options.height === "auto" ) {
                this.element.css({
                    minheight: mincontentheight,
                    maxheight: maxcontentheight,
                    height: "auto"
                });
            } else {
                this.element.height( math.max( 0, options.height - noncontentheight ) );
            }

            if ( this.uidialog.is( ":data(ui-resizable)" ) ) {
                this.uidialog.resizable( "option", "minheight", this._minheight() );
            }
        },

        _blockframes: function() {
            this.iframeblocks = this.document.find( "iframe" ).map(function() {
                var iframe = $( this );

                return $( "<div>" )
                    .css({
                        position: "absolute",
                        width: iframe.outerwidth(),
                        height: iframe.outerheight()
                    })
                    .appendto( iframe.parent() )
                    .offset( iframe.offset() )[0];
            });
        },

        _unblockframes: function() {
            if ( this.iframeblocks ) {
                this.iframeblocks.remove();
                delete this.iframeblocks;
            }
        },

        _allowinteraction: function( event ) {
            if ( $( event.target ).closest( ".ui-dialog" ).length ) {
                return true;
            }

            // todo: remove hack when datepicker implements
            // the .ui-front logic (#8989)
            return !!$( event.target ).closest( ".ui-datepicker" ).length;
        },

        _createoverlay: function() {
            if ( !this.options.modal ) {
                return;
            }

            // we use a delay in case the overlay is created from an
            // event that we're going to be cancelling (#2804)
            var isopening = true;
            this._delay(function() {
                isopening = false;
            });

            if ( !this.document.data( "ui-dialog-overlays" ) ) {

                // prevent use of anchors and inputs
                // using _on() for an event handler shared across many instances is
                // safe because the dialogs stack and must be closed in reverse order
                this._on( this.document, {
                    focusin: function( event ) {
                        if ( isopening ) {
                            return;
                        }

                        if ( !this._allowinteraction( event ) ) {
                            event.preventdefault();
                            this._trackinginstances()[ 0 ]._focustabbable();
                        }
                    }
                });
            }

            this.overlay = $( "<div>" )
                .addclass( "ui-widget-overlay ui-front" )
                .appendto( this._appendto() );
            this._on( this.overlay, {
                mousedown: "_keepfocus"
            });
            this.document.data( "ui-dialog-overlays",
                    (this.document.data( "ui-dialog-overlays" ) || 0) + 1 );
        },

        _destroyoverlay: function() {
            if ( !this.options.modal ) {
                return;
            }

            if ( this.overlay ) {
                var overlays = this.document.data( "ui-dialog-overlays" ) - 1;

                if ( !overlays ) {
                    this.document
                        .unbind( "focusin" )
                        .removedata( "ui-dialog-overlays" );
                } else {
                    this.document.data( "ui-dialog-overlays", overlays );
                }

                this.overlay.remove();
                this.overlay = null;
            }
        }
    });


    /*!
     * jquery ui droppable 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/droppable/
     */


    $.widget( "ui.droppable", {
        version: "1.11.2",
        widgeteventprefix: "drop",
        options: {
            accept: "*",
            activeclass: false,
            addclasses: true,
            greedy: false,
            hoverclass: false,
            scope: "default",
            tolerance: "intersect",

            // callbacks
            activate: null,
            deactivate: null,
            drop: null,
            out: null,
            over: null
        },
        _create: function() {

            var proportions,
                o = this.options,
                accept = o.accept;

            this.isover = false;
            this.isout = true;

            this.accept = $.isfunction( accept ) ? accept : function( d ) {
                return d.is( accept );
            };

            this.proportions = function( /* valuetowrite */ ) {
                if ( arguments.length ) {
                    // store the droppable's proportions
                    proportions = arguments[ 0 ];
                } else {
                    // retrieve or derive the droppable's proportions
                    return proportions ?
                        proportions :
                        proportions = {
                            width: this.element[ 0 ].offsetwidth,
                            height: this.element[ 0 ].offsetheight
                        };
                }
            };

            this._addtomanager( o.scope );

            o.addclasses && this.element.addclass( "ui-droppable" );

        },

        _addtomanager: function( scope ) {
            // add the reference and positions to the manager
            $.ui.ddmanager.droppables[ scope ] = $.ui.ddmanager.droppables[ scope ] || [];
            $.ui.ddmanager.droppables[ scope ].push( this );
        },

        _splice: function( drop ) {
            var i = 0;
            for ( ; i < drop.length; i++ ) {
                if ( drop[ i ] === this ) {
                    drop.splice( i, 1 );
                }
            }
        },

        _destroy: function() {
            var drop = $.ui.ddmanager.droppables[ this.options.scope ];

            this._splice( drop );

            this.element.removeclass( "ui-droppable ui-droppable-disabled" );
        },

        _setoption: function( key, value ) {

            if ( key === "accept" ) {
                this.accept = $.isfunction( value ) ? value : function( d ) {
                    return d.is( value );
                };
            } else if ( key === "scope" ) {
                var drop = $.ui.ddmanager.droppables[ this.options.scope ];

                this._splice( drop );
                this._addtomanager( value );
            }

            this._super( key, value );
        },

        _activate: function( event ) {
            var draggable = $.ui.ddmanager.current;
            if ( this.options.activeclass ) {
                this.element.addclass( this.options.activeclass );
            }
            if ( draggable ){
                this._trigger( "activate", event, this.ui( draggable ) );
            }
        },

        _deactivate: function( event ) {
            var draggable = $.ui.ddmanager.current;
            if ( this.options.activeclass ) {
                this.element.removeclass( this.options.activeclass );
            }
            if ( draggable ){
                this._trigger( "deactivate", event, this.ui( draggable ) );
            }
        },

        _over: function( event ) {

            var draggable = $.ui.ddmanager.current;

            // bail if draggable and droppable are same element
            if ( !draggable || ( draggable.currentitem || draggable.element )[ 0 ] === this.element[ 0 ] ) {
                return;
            }

            if ( this.accept.call( this.element[ 0 ], ( draggable.currentitem || draggable.element ) ) ) {
                if ( this.options.hoverclass ) {
                    this.element.addclass( this.options.hoverclass );
                }
                this._trigger( "over", event, this.ui( draggable ) );
            }

        },

        _out: function( event ) {

            var draggable = $.ui.ddmanager.current;

            // bail if draggable and droppable are same element
            if ( !draggable || ( draggable.currentitem || draggable.element )[ 0 ] === this.element[ 0 ] ) {
                return;
            }

            if ( this.accept.call( this.element[ 0 ], ( draggable.currentitem || draggable.element ) ) ) {
                if ( this.options.hoverclass ) {
                    this.element.removeclass( this.options.hoverclass );
                }
                this._trigger( "out", event, this.ui( draggable ) );
            }

        },

        _drop: function( event, custom ) {

            var draggable = custom || $.ui.ddmanager.current,
                childrenintersection = false;

            // bail if draggable and droppable are same element
            if ( !draggable || ( draggable.currentitem || draggable.element )[ 0 ] === this.element[ 0 ] ) {
                return false;
            }

            this.element.find( ":data(ui-droppable)" ).not( ".ui-draggable-dragging" ).each(function() {
                var inst = $( this ).droppable( "instance" );
                if (
                    inst.options.greedy &&
                    !inst.options.disabled &&
                    inst.options.scope === draggable.options.scope &&
                    inst.accept.call( inst.element[ 0 ], ( draggable.currentitem || draggable.element ) ) &&
                    $.ui.intersect( draggable, $.extend( inst, { offset: inst.element.offset() } ), inst.options.tolerance, event )
                    ) { childrenintersection = true; return false; }
            });
            if ( childrenintersection ) {
                return false;
            }

            if ( this.accept.call( this.element[ 0 ], ( draggable.currentitem || draggable.element ) ) ) {
                if ( this.options.activeclass ) {
                    this.element.removeclass( this.options.activeclass );
                }
                if ( this.options.hoverclass ) {
                    this.element.removeclass( this.options.hoverclass );
                }
                this._trigger( "drop", event, this.ui( draggable ) );
                return this.element;
            }

            return false;

        },

        ui: function( c ) {
            return {
                draggable: ( c.currentitem || c.element ),
                helper: c.helper,
                position: c.position,
                offset: c.positionabs
            };
        }

    });

    $.ui.intersect = (function() {
        function isoveraxis( x, reference, size ) {
            return ( x >= reference ) && ( x < ( reference + size ) );
        }

        return function( draggable, droppable, tolerancemode, event ) {

            if ( !droppable.offset ) {
                return false;
            }

            var x1 = ( draggable.positionabs || draggable.position.absolute ).left + draggable.margins.left,
                y1 = ( draggable.positionabs || draggable.position.absolute ).top + draggable.margins.top,
                x2 = x1 + draggable.helperproportions.width,
                y2 = y1 + draggable.helperproportions.height,
                l = droppable.offset.left,
                t = droppable.offset.top,
                r = l + droppable.proportions().width,
                b = t + droppable.proportions().height;

            switch ( tolerancemode ) {
                case "fit":
                    return ( l <= x1 && x2 <= r && t <= y1 && y2 <= b );
                case "intersect":
                    return ( l < x1 + ( draggable.helperproportions.width / 2 ) && // right half
                        x2 - ( draggable.helperproportions.width / 2 ) < r && // left half
                        t < y1 + ( draggable.helperproportions.height / 2 ) && // bottom half
                        y2 - ( draggable.helperproportions.height / 2 ) < b ); // top half
                case "pointer":
                    return isoveraxis( event.pagey, t, droppable.proportions().height ) && isoveraxis( event.pagex, l, droppable.proportions().width );
                case "touch":
                    return (
                        ( y1 >= t && y1 <= b ) || // top edge touching
                        ( y2 >= t && y2 <= b ) || // bottom edge touching
                        ( y1 < t && y2 > b ) // surrounded vertically
                        ) && (
                        ( x1 >= l && x1 <= r ) || // left edge touching
                        ( x2 >= l && x2 <= r ) || // right edge touching
                        ( x1 < l && x2 > r ) // surrounded horizontally
                        );
                default:
                    return false;
            }
        };
    })();

    /*
     this manager tracks offsets of draggables and droppables
     */
    $.ui.ddmanager = {
        current: null,
        droppables: { "default": [] },
        prepareoffsets: function( t, event ) {

            var i, j,
                m = $.ui.ddmanager.droppables[ t.options.scope ] || [],
                type = event ? event.type : null, // workaround for #2317
                list = ( t.currentitem || t.element ).find( ":data(ui-droppable)" ).addback();

            droppablesloop: for ( i = 0; i < m.length; i++ ) {

                // no disabled and non-accepted
                if ( m[ i ].options.disabled || ( t && !m[ i ].accept.call( m[ i ].element[ 0 ], ( t.currentitem || t.element ) ) ) ) {
                    continue;
                }

                // filter out elements in the current dragged item
                for ( j = 0; j < list.length; j++ ) {
                    if ( list[ j ] === m[ i ].element[ 0 ] ) {
                        m[ i ].proportions().height = 0;
                        continue droppablesloop;
                    }
                }

                m[ i ].visible = m[ i ].element.css( "display" ) !== "none";
                if ( !m[ i ].visible ) {
                    continue;
                }

                // activate the droppable if used directly from draggables
                if ( type === "mousedown" ) {
                    m[ i ]._activate.call( m[ i ], event );
                }

                m[ i ].offset = m[ i ].element.offset();
                m[ i ].proportions({ width: m[ i ].element[ 0 ].offsetwidth, height: m[ i ].element[ 0 ].offsetheight });

            }

        },
        drop: function( draggable, event ) {

            var dropped = false;
            // create a copy of the droppables in case the list changes during the drop (#9116)
            $.each( ( $.ui.ddmanager.droppables[ draggable.options.scope ] || [] ).slice(), function() {

                if ( !this.options ) {
                    return;
                }
                if ( !this.options.disabled && this.visible && $.ui.intersect( draggable, this, this.options.tolerance, event ) ) {
                    dropped = this._drop.call( this, event ) || dropped;
                }

                if ( !this.options.disabled && this.visible && this.accept.call( this.element[ 0 ], ( draggable.currentitem || draggable.element ) ) ) {
                    this.isout = true;
                    this.isover = false;
                    this._deactivate.call( this, event );
                }

            });
            return dropped;

        },
        dragstart: function( draggable, event ) {
            // listen for scrolling so that if the dragging causes scrolling the position of the droppables can be recalculated (see #5003)
            draggable.element.parentsuntil( "body" ).bind( "scroll.droppable", function() {
                if ( !draggable.options.refreshpositions ) {
                    $.ui.ddmanager.prepareoffsets( draggable, event );
                }
            });
        },
        drag: function( draggable, event ) {

            // if you have a highly dynamic page, you might try this option. it renders positions every time you move the mouse.
            if ( draggable.options.refreshpositions ) {
                $.ui.ddmanager.prepareoffsets( draggable, event );
            }

            // run through all droppables and check their positions based on specific tolerance options
            $.each( $.ui.ddmanager.droppables[ draggable.options.scope ] || [], function() {

                if ( this.options.disabled || this.greedychild || !this.visible ) {
                    return;
                }

                var parentinstance, scope, parent,
                    intersects = $.ui.intersect( draggable, this, this.options.tolerance, event ),
                    c = !intersects && this.isover ? "isout" : ( intersects && !this.isover ? "isover" : null );
                if ( !c ) {
                    return;
                }

                if ( this.options.greedy ) {
                    // find droppable parents with same scope
                    scope = this.options.scope;
                    parent = this.element.parents( ":data(ui-droppable)" ).filter(function() {
                        return $( this ).droppable( "instance" ).options.scope === scope;
                    });

                    if ( parent.length ) {
                        parentinstance = $( parent[ 0 ] ).droppable( "instance" );
                        parentinstance.greedychild = ( c === "isover" );
                    }
                }

                // we just moved into a greedy child
                if ( parentinstance && c === "isover" ) {
                    parentinstance.isover = false;
                    parentinstance.isout = true;
                    parentinstance._out.call( parentinstance, event );
                }

                this[ c ] = true;
                this[c === "isout" ? "isover" : "isout"] = false;
                this[c === "isover" ? "_over" : "_out"].call( this, event );

                // we just moved out of a greedy child
                if ( parentinstance && c === "isout" ) {
                    parentinstance.isout = false;
                    parentinstance.isover = true;
                    parentinstance._over.call( parentinstance, event );
                }
            });

        },
        dragstop: function( draggable, event ) {
            draggable.element.parentsuntil( "body" ).unbind( "scroll.droppable" );
            // call prepareoffsets one final time since ie does not fire return scroll events when overflow was caused by drag (see #5003)
            if ( !draggable.options.refreshpositions ) {
                $.ui.ddmanager.prepareoffsets( draggable, event );
            }
        }
    };

    var droppable = $.ui.droppable;


    /*!
     * jquery ui effects 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/category/effects-core/
     */


    var dataspace = "ui-effects-",

    // create a local jquery because jquery color relies on it and the
    // global may not exist with amd and a custom build (#10199)
        jquery = $;

    $.effects = {
        effect: {}
    };

    /*!
     * jquery color animations v2.1.2
     * https://github.com/jquery/jquery-color
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * date: wed jan 16 08:47:09 2013 -0600
     */
    (function( jquery, undefined ) {

        var stephooks = "backgroundcolor borderbottomcolor borderleftcolor borderrightcolor bordertopcolor color columnrulecolor outlinecolor textdecorationcolor textemphasiscolor",

        // plusequals test for += 100 -= 100
            rplusequals = /^([\-+])=\s*(\d+\.?\d*)/,
        // a set of re's that can match strings and generate color tuples.
            stringparsers = [ {
                re: /rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*(\d?(?:\.\d+)?)\s*)?\)/,
                parse: function( execresult ) {
                    return [
                        execresult[ 1 ],
                        execresult[ 2 ],
                        execresult[ 3 ],
                        execresult[ 4 ]
                    ];
                }
            }, {
                re: /rgba?\(\s*(\d+(?:\.\d+)?)\%\s*,\s*(\d+(?:\.\d+)?)\%\s*,\s*(\d+(?:\.\d+)?)\%\s*(?:,\s*(\d?(?:\.\d+)?)\s*)?\)/,
                parse: function( execresult ) {
                    return [
                            execresult[ 1 ] * 2.55,
                            execresult[ 2 ] * 2.55,
                            execresult[ 3 ] * 2.55,
                        execresult[ 4 ]
                    ];
                }
            }, {
                // this regex ignores a-f because it's compared against an already lowercased string
                re: /#([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})/,
                parse: function( execresult ) {
                    return [
                        parseint( execresult[ 1 ], 16 ),
                        parseint( execresult[ 2 ], 16 ),
                        parseint( execresult[ 3 ], 16 )
                    ];
                }
            }, {
                // this regex ignores a-f because it's compared against an already lowercased string
                re: /#([a-f0-9])([a-f0-9])([a-f0-9])/,
                parse: function( execresult ) {
                    return [
                        parseint( execresult[ 1 ] + execresult[ 1 ], 16 ),
                        parseint( execresult[ 2 ] + execresult[ 2 ], 16 ),
                        parseint( execresult[ 3 ] + execresult[ 3 ], 16 )
                    ];
                }
            }, {
                re: /hsla?\(\s*(\d+(?:\.\d+)?)\s*,\s*(\d+(?:\.\d+)?)\%\s*,\s*(\d+(?:\.\d+)?)\%\s*(?:,\s*(\d?(?:\.\d+)?)\s*)?\)/,
                space: "hsla",
                parse: function( execresult ) {
                    return [
                        execresult[ 1 ],
                            execresult[ 2 ] / 100,
                            execresult[ 3 ] / 100,
                        execresult[ 4 ]
                    ];
                }
            } ],

        // jquery.color( )
            color = jquery.color = function( color, green, blue, alpha ) {
                return new jquery.color.fn.parse( color, green, blue, alpha );
            },
            spaces = {
                rgba: {
                    props: {
                        red: {
                            idx: 0,
                            type: "byte"
                        },
                        green: {
                            idx: 1,
                            type: "byte"
                        },
                        blue: {
                            idx: 2,
                            type: "byte"
                        }
                    }
                },

                hsla: {
                    props: {
                        hue: {
                            idx: 0,
                            type: "degrees"
                        },
                        saturation: {
                            idx: 1,
                            type: "percent"
                        },
                        lightness: {
                            idx: 2,
                            type: "percent"
                        }
                    }
                }
            },
            proptypes = {
                "byte": {
                    floor: true,
                    max: 255
                },
                "percent": {
                    max: 1
                },
                "degrees": {
                    mod: 360,
                    floor: true
                }
            },
            support = color.support = {},

        // element for support tests
            supportelem = jquery( "<p>" )[ 0 ],

        // colors = jquery.color.names
            colors,

        // local aliases of functions called often
            each = jquery.each;

// determine rgba support immediately
        supportelem.style.csstext = "background-color:rgba(1,1,1,.5)";
        support.rgba = supportelem.style.backgroundcolor.indexof( "rgba" ) > -1;

// define cache name and alpha properties
// for rgba and hsla spaces
        each( spaces, function( spacename, space ) {
            space.cache = "_" + spacename;
            space.props.alpha = {
                idx: 3,
                type: "percent",
                def: 1
            };
        });

        function clamp( value, prop, allowempty ) {
            var type = proptypes[ prop.type ] || {};

            if ( value == null ) {
                return (allowempty || !prop.def) ? null : prop.def;
            }

            // ~~ is an short way of doing floor for positive numbers
            value = type.floor ? ~~value : parsefloat( value );

            // ie will pass in empty strings as value for alpha,
            // which will hit this case
            if ( isnan( value ) ) {
                return prop.def;
            }

            if ( type.mod ) {
                // we add mod before modding to make sure that negatives values
                // get converted properly: -10 -> 350
                return (value + type.mod) % type.mod;
            }

            // for now all property types without mod have min and max
            return 0 > value ? 0 : type.max < value ? type.max : value;
        }

        function stringparse( string ) {
            var inst = color(),
                rgba = inst._rgba = [];

            string = string.tolowercase();

            each( stringparsers, function( i, parser ) {
                var parsed,
                    match = parser.re.exec( string ),
                    values = match && parser.parse( match ),
                    spacename = parser.space || "rgba";

                if ( values ) {
                    parsed = inst[ spacename ]( values );

                    // if this was an rgba parse the assignment might happen twice
                    // oh well....
                    inst[ spaces[ spacename ].cache ] = parsed[ spaces[ spacename ].cache ];
                    rgba = inst._rgba = parsed._rgba;

                    // exit each( stringparsers ) here because we matched
                    return false;
                }
            });

            // found a stringparser that handled it
            if ( rgba.length ) {

                // if this came from a parsed string, force "transparent" when alpha is 0
                // chrome, (and maybe others) return "transparent" as rgba(0,0,0,0)
                if ( rgba.join() === "0,0,0,0" ) {
                    jquery.extend( rgba, colors.transparent );
                }
                return inst;
            }

            // named colors
            return colors[ string ];
        }

        color.fn = jquery.extend( color.prototype, {
            parse: function( red, green, blue, alpha ) {
                if ( red === undefined ) {
                    this._rgba = [ null, null, null, null ];
                    return this;
                }
                if ( red.jquery || red.nodetype ) {
                    red = jquery( red ).css( green );
                    green = undefined;
                }

                var inst = this,
                    type = jquery.type( red ),
                    rgba = this._rgba = [];

                // more than 1 argument specified - assume ( red, green, blue, alpha )
                if ( green !== undefined ) {
                    red = [ red, green, blue, alpha ];
                    type = "array";
                }

                if ( type === "string" ) {
                    return this.parse( stringparse( red ) || colors._default );
                }

                if ( type === "array" ) {
                    each( spaces.rgba.props, function( key, prop ) {
                        rgba[ prop.idx ] = clamp( red[ prop.idx ], prop );
                    });
                    return this;
                }

                if ( type === "object" ) {
                    if ( red instanceof color ) {
                        each( spaces, function( spacename, space ) {
                            if ( red[ space.cache ] ) {
                                inst[ space.cache ] = red[ space.cache ].slice();
                            }
                        });
                    } else {
                        each( spaces, function( spacename, space ) {
                            var cache = space.cache;
                            each( space.props, function( key, prop ) {

                                // if the cache doesn't exist, and we know how to convert
                                if ( !inst[ cache ] && space.to ) {

                                    // if the value was null, we don't need to copy it
                                    // if the key was alpha, we don't need to copy it either
                                    if ( key === "alpha" || red[ key ] == null ) {
                                        return;
                                    }
                                    inst[ cache ] = space.to( inst._rgba );
                                }

                                // this is the only case where we allow nulls for all properties.
                                // call clamp with alwaysallowempty
                                inst[ cache ][ prop.idx ] = clamp( red[ key ], prop, true );
                            });

                            // everything defined but alpha?
                            if ( inst[ cache ] && jquery.inarray( null, inst[ cache ].slice( 0, 3 ) ) < 0 ) {
                                // use the default of 1
                                inst[ cache ][ 3 ] = 1;
                                if ( space.from ) {
                                    inst._rgba = space.from( inst[ cache ] );
                                }
                            }
                        });
                    }
                    return this;
                }
            },
            is: function( compare ) {
                var is = color( compare ),
                    same = true,
                    inst = this;

                each( spaces, function( _, space ) {
                    var localcache,
                        iscache = is[ space.cache ];
                    if (iscache) {
                        localcache = inst[ space.cache ] || space.to && space.to( inst._rgba ) || [];
                        each( space.props, function( _, prop ) {
                            if ( iscache[ prop.idx ] != null ) {
                                same = ( iscache[ prop.idx ] === localcache[ prop.idx ] );
                                return same;
                            }
                        });
                    }
                    return same;
                });
                return same;
            },
            _space: function() {
                var used = [],
                    inst = this;
                each( spaces, function( spacename, space ) {
                    if ( inst[ space.cache ] ) {
                        used.push( spacename );
                    }
                });
                return used.pop();
            },
            transition: function( other, distance ) {
                var end = color( other ),
                    spacename = end._space(),
                    space = spaces[ spacename ],
                    startcolor = this.alpha() === 0 ? color( "transparent" ) : this,
                    start = startcolor[ space.cache ] || space.to( startcolor._rgba ),
                    result = start.slice();

                end = end[ space.cache ];
                each( space.props, function( key, prop ) {
                    var index = prop.idx,
                        startvalue = start[ index ],
                        endvalue = end[ index ],
                        type = proptypes[ prop.type ] || {};

                    // if null, don't override start value
                    if ( endvalue === null ) {
                        return;
                    }
                    // if null - use end
                    if ( startvalue === null ) {
                        result[ index ] = endvalue;
                    } else {
                        if ( type.mod ) {
                            if ( endvalue - startvalue > type.mod / 2 ) {
                                startvalue += type.mod;
                            } else if ( startvalue - endvalue > type.mod / 2 ) {
                                startvalue -= type.mod;
                            }
                        }
                        result[ index ] = clamp( ( endvalue - startvalue ) * distance + startvalue, prop );
                    }
                });
                return this[ spacename ]( result );
            },
            blend: function( opaque ) {
                // if we are already opaque - return ourself
                if ( this._rgba[ 3 ] === 1 ) {
                    return this;
                }

                var rgb = this._rgba.slice(),
                    a = rgb.pop(),
                    blend = color( opaque )._rgba;

                return color( jquery.map( rgb, function( v, i ) {
                    return ( 1 - a ) * blend[ i ] + a * v;
                }));
            },
            torgbastring: function() {
                var prefix = "rgba(",
                    rgba = jquery.map( this._rgba, function( v, i ) {
                        return v == null ? ( i > 2 ? 1 : 0 ) : v;
                    });

                if ( rgba[ 3 ] === 1 ) {
                    rgba.pop();
                    prefix = "rgb(";
                }

                return prefix + rgba.join() + ")";
            },
            tohslastring: function() {
                var prefix = "hsla(",
                    hsla = jquery.map( this.hsla(), function( v, i ) {
                        if ( v == null ) {
                            v = i > 2 ? 1 : 0;
                        }

                        // catch 1 and 2
                        if ( i && i < 3 ) {
                            v = math.round( v * 100 ) + "%";
                        }
                        return v;
                    });

                if ( hsla[ 3 ] === 1 ) {
                    hsla.pop();
                    prefix = "hsl(";
                }
                return prefix + hsla.join() + ")";
            },
            tohexstring: function( includealpha ) {
                var rgba = this._rgba.slice(),
                    alpha = rgba.pop();

                if ( includealpha ) {
                    rgba.push( ~~( alpha * 255 ) );
                }

                return "#" + jquery.map( rgba, function( v ) {

                    // default to 0 when nulls exist
                    v = ( v || 0 ).tostring( 16 );
                    return v.length === 1 ? "0" + v : v;
                }).join("");
            },
            tostring: function() {
                return this._rgba[ 3 ] === 0 ? "transparent" : this.torgbastring();
            }
        });
        color.fn.parse.prototype = color.fn;

// hsla conversions adapted from:
// https://code.google.com/p/maashaack/source/browse/packages/graphics/trunk/src/graphics/colors/hue2rgb.as?r=5021

        function hue2rgb( p, q, h ) {
            h = ( h + 1 ) % 1;
            if ( h * 6 < 1 ) {
                return p + ( q - p ) * h * 6;
            }
            if ( h * 2 < 1) {
                return q;
            }
            if ( h * 3 < 2 ) {
                return p + ( q - p ) * ( ( 2 / 3 ) - h ) * 6;
            }
            return p;
        }

        spaces.hsla.to = function( rgba ) {
            if ( rgba[ 0 ] == null || rgba[ 1 ] == null || rgba[ 2 ] == null ) {
                return [ null, null, null, rgba[ 3 ] ];
            }
            var r = rgba[ 0 ] / 255,
                g = rgba[ 1 ] / 255,
                b = rgba[ 2 ] / 255,
                a = rgba[ 3 ],
                max = math.max( r, g, b ),
                min = math.min( r, g, b ),
                diff = max - min,
                add = max + min,
                l = add * 0.5,
                h, s;

            if ( min === max ) {
                h = 0;
            } else if ( r === max ) {
                h = ( 60 * ( g - b ) / diff ) + 360;
            } else if ( g === max ) {
                h = ( 60 * ( b - r ) / diff ) + 120;
            } else {
                h = ( 60 * ( r - g ) / diff ) + 240;
            }

            // chroma (diff) == 0 means greyscale which, by definition, saturation = 0%
            // otherwise, saturation is based on the ratio of chroma (diff) to lightness (add)
            if ( diff === 0 ) {
                s = 0;
            } else if ( l <= 0.5 ) {
                s = diff / add;
            } else {
                s = diff / ( 2 - add );
            }
            return [ math.round(h) % 360, s, l, a == null ? 1 : a ];
        };

        spaces.hsla.from = function( hsla ) {
            if ( hsla[ 0 ] == null || hsla[ 1 ] == null || hsla[ 2 ] == null ) {
                return [ null, null, null, hsla[ 3 ] ];
            }
            var h = hsla[ 0 ] / 360,
                s = hsla[ 1 ],
                l = hsla[ 2 ],
                a = hsla[ 3 ],
                q = l <= 0.5 ? l * ( 1 + s ) : l + s - l * s,
                p = 2 * l - q;

            return [
                math.round( hue2rgb( p, q, h + ( 1 / 3 ) ) * 255 ),
                math.round( hue2rgb( p, q, h ) * 255 ),
                math.round( hue2rgb( p, q, h - ( 1 / 3 ) ) * 255 ),
                a
            ];
        };

        each( spaces, function( spacename, space ) {
            var props = space.props,
                cache = space.cache,
                to = space.to,
                from = space.from;

            // makes rgba() and hsla()
            color.fn[ spacename ] = function( value ) {

                // generate a cache for this space if it doesn't exist
                if ( to && !this[ cache ] ) {
                    this[ cache ] = to( this._rgba );
                }
                if ( value === undefined ) {
                    return this[ cache ].slice();
                }

                var ret,
                    type = jquery.type( value ),
                    arr = ( type === "array" || type === "object" ) ? value : arguments,
                    local = this[ cache ].slice();

                each( props, function( key, prop ) {
                    var val = arr[ type === "object" ? key : prop.idx ];
                    if ( val == null ) {
                        val = local[ prop.idx ];
                    }
                    local[ prop.idx ] = clamp( val, prop );
                });

                if ( from ) {
                    ret = color( from( local ) );
                    ret[ cache ] = local;
                    return ret;
                } else {
                    return color( local );
                }
            };

            // makes red() green() blue() alpha() hue() saturation() lightness()
            each( props, function( key, prop ) {
                // alpha is included in more than one space
                if ( color.fn[ key ] ) {
                    return;
                }
                color.fn[ key ] = function( value ) {
                    var vtype = jquery.type( value ),
                        fn = ( key === "alpha" ? ( this._hsla ? "hsla" : "rgba" ) : spacename ),
                        local = this[ fn ](),
                        cur = local[ prop.idx ],
                        match;

                    if ( vtype === "undefined" ) {
                        return cur;
                    }

                    if ( vtype === "function" ) {
                        value = value.call( this, cur );
                        vtype = jquery.type( value );
                    }
                    if ( value == null && prop.empty ) {
                        return this;
                    }
                    if ( vtype === "string" ) {
                        match = rplusequals.exec( value );
                        if ( match ) {
                            value = cur + parsefloat( match[ 2 ] ) * ( match[ 1 ] === "+" ? 1 : -1 );
                        }
                    }
                    local[ prop.idx ] = value;
                    return this[ fn ]( local );
                };
            });
        });

// add csshook and .fx.step function for each named hook.
// accept a space separated string of properties
        color.hook = function( hook ) {
            var hooks = hook.split( " " );
            each( hooks, function( i, hook ) {
                jquery.csshooks[ hook ] = {
                    set: function( elem, value ) {
                        var parsed, curelem,
                            backgroundcolor = "";

                        if ( value !== "transparent" && ( jquery.type( value ) !== "string" || ( parsed = stringparse( value ) ) ) ) {
                            value = color( parsed || value );
                            if ( !support.rgba && value._rgba[ 3 ] !== 1 ) {
                                curelem = hook === "backgroundcolor" ? elem.parentnode : elem;
                                while (
                                    (backgroundcolor === "" || backgroundcolor === "transparent") &&
                                    curelem && curelem.style
                                    ) {
                                    try {
                                        backgroundcolor = jquery.css( curelem, "backgroundcolor" );
                                        curelem = curelem.parentnode;
                                    } catch ( e ) {
                                    }
                                }

                                value = value.blend( backgroundcolor && backgroundcolor !== "transparent" ?
                                    backgroundcolor :
                                    "_default" );
                            }

                            value = value.torgbastring();
                        }
                        try {
                            elem.style[ hook ] = value;
                        } catch ( e ) {
                            // wrapped to prevent ie from throwing errors on "invalid" values like 'auto' or 'inherit'
                        }
                    }
                };
                jquery.fx.step[ hook ] = function( fx ) {
                    if ( !fx.colorinit ) {
                        fx.start = color( fx.elem, hook );
                        fx.end = color( fx.end );
                        fx.colorinit = true;
                    }
                    jquery.csshooks[ hook ].set( fx.elem, fx.start.transition( fx.end, fx.pos ) );
                };
            });

        };

        color.hook( stephooks );

        jquery.csshooks.bordercolor = {
            expand: function( value ) {
                var expanded = {};

                each( [ "top", "right", "bottom", "left" ], function( i, part ) {
                    expanded[ "border" + part + "color" ] = value;
                });
                return expanded;
            }
        };

// basic color names only.
// usage of any of the other color names requires adding yourself or including
// jquery.color.svg-names.js.
        colors = jquery.color.names = {
            // 4.1. basic color keywords
            aqua: "#00ffff",
            black: "#000000",
            blue: "#0000ff",
            fuchsia: "#ff00ff",
            gray: "#808080",
            green: "#008000",
            lime: "#00ff00",
            maroon: "#800000",
            navy: "#000080",
            olive: "#808000",
            purple: "#800080",
            red: "#ff0000",
            silver: "#c0c0c0",
            teal: "#008080",
            white: "#ffffff",
            yellow: "#ffff00",

            // 4.2.3. "transparent" color keyword
            transparent: [ null, null, null, 0 ],

            _default: "#ffffff"
        };

    })( jquery );

    /******************************************************************************/
    /****************************** class animations ******************************/
    /******************************************************************************/
    (function() {

        var classanimationactions = [ "add", "remove", "toggle" ],
            shorthandstyles = {
                border: 1,
                borderbottom: 1,
                bordercolor: 1,
                borderleft: 1,
                borderright: 1,
                bordertop: 1,
                borderwidth: 1,
                margin: 1,
                padding: 1
            };

        $.each([ "borderleftstyle", "borderrightstyle", "borderbottomstyle", "bordertopstyle" ], function( _, prop ) {
            $.fx.step[ prop ] = function( fx ) {
                if ( fx.end !== "none" && !fx.setattr || fx.pos === 1 && !fx.setattr ) {
                    jquery.style( fx.elem, prop, fx.end );
                    fx.setattr = true;
                }
            };
        });

        function getelementstyles( elem ) {
            var key, len,
                style = elem.ownerdocument.defaultview ?
                    elem.ownerdocument.defaultview.getcomputedstyle( elem, null ) :
                    elem.currentstyle,
                styles = {};

            if ( style && style.length && style[ 0 ] && style[ style[ 0 ] ] ) {
                len = style.length;
                while ( len-- ) {
                    key = style[ len ];
                    if ( typeof style[ key ] === "string" ) {
                        styles[ $.camelcase( key ) ] = style[ key ];
                    }
                }
                // support: opera, ie <9
            } else {
                for ( key in style ) {
                    if ( typeof style[ key ] === "string" ) {
                        styles[ key ] = style[ key ];
                    }
                }
            }

            return styles;
        }

        function styledifference( oldstyle, newstyle ) {
            var diff = {},
                name, value;

            for ( name in newstyle ) {
                value = newstyle[ name ];
                if ( oldstyle[ name ] !== value ) {
                    if ( !shorthandstyles[ name ] ) {
                        if ( $.fx.step[ name ] || !isnan( parsefloat( value ) ) ) {
                            diff[ name ] = value;
                        }
                    }
                }
            }

            return diff;
        }

// support: jquery <1.8
        if ( !$.fn.addback ) {
            $.fn.addback = function( selector ) {
                return this.add( selector == null ?
                        this.prevobject : this.prevobject.filter( selector )
                );
            };
        }

        $.effects.animateclass = function( value, duration, easing, callback ) {
            var o = $.speed( duration, easing, callback );

            return this.queue( function() {
                var animated = $( this ),
                    baseclass = animated.attr( "class" ) || "",
                    applyclasschange,
                    allanimations = o.children ? animated.find( "*" ).addback() : animated;

                // map the animated objects to store the original styles.
                allanimations = allanimations.map(function() {
                    var el = $( this );
                    return {
                        el: el,
                        start: getelementstyles( this )
                    };
                });

                // apply class change
                applyclasschange = function() {
                    $.each( classanimationactions, function(i, action) {
                        if ( value[ action ] ) {
                            animated[ action + "class" ]( value[ action ] );
                        }
                    });
                };
                applyclasschange();

                // map all animated objects again - calculate new styles and diff
                allanimations = allanimations.map(function() {
                    this.end = getelementstyles( this.el[ 0 ] );
                    this.diff = styledifference( this.start, this.end );
                    return this;
                });

                // apply original class
                animated.attr( "class", baseclass );

                // map all animated objects again - this time collecting a promise
                allanimations = allanimations.map(function() {
                    var styleinfo = this,
                        dfd = $.deferred(),
                        opts = $.extend({}, o, {
                            queue: false,
                            complete: function() {
                                dfd.resolve( styleinfo );
                            }
                        });

                    this.el.animate( this.diff, opts );
                    return dfd.promise();
                });

                // once all animations have completed:
                $.when.apply( $, allanimations.get() ).done(function() {

                    // set the final class
                    applyclasschange();

                    // for each animated element,
                    // clear all css properties that were animated
                    $.each( arguments, function() {
                        var el = this.el;
                        $.each( this.diff, function(key) {
                            el.css( key, "" );
                        });
                    });

                    // this is guarnteed to be there if you use jquery.speed()
                    // it also handles dequeuing the next anim...
                    o.complete.call( animated[ 0 ] );
                });
            });
        };

        $.fn.extend({
            addclass: (function( orig ) {
                return function( classnames, speed, easing, callback ) {
                    return speed ?
                        $.effects.animateclass.call( this,
                            { add: classnames }, speed, easing, callback ) :
                        orig.apply( this, arguments );
                };
            })( $.fn.addclass ),

            removeclass: (function( orig ) {
                return function( classnames, speed, easing, callback ) {
                    return arguments.length > 1 ?
                        $.effects.animateclass.call( this,
                            { remove: classnames }, speed, easing, callback ) :
                        orig.apply( this, arguments );
                };
            })( $.fn.removeclass ),

            toggleclass: (function( orig ) {
                return function( classnames, force, speed, easing, callback ) {
                    if ( typeof force === "boolean" || force === undefined ) {
                        if ( !speed ) {
                            // without speed parameter
                            return orig.apply( this, arguments );
                        } else {
                            return $.effects.animateclass.call( this,
                                (force ? { add: classnames } : { remove: classnames }),
                                speed, easing, callback );
                        }
                    } else {
                        // without force parameter
                        return $.effects.animateclass.call( this,
                            { toggle: classnames }, force, speed, easing );
                    }
                };
            })( $.fn.toggleclass ),

            switchclass: function( remove, add, speed, easing, callback) {
                return $.effects.animateclass.call( this, {
                    add: add,
                    remove: remove
                }, speed, easing, callback );
            }
        });

    })();

    /******************************************************************************/
    /*********************************** effects **********************************/
    /******************************************************************************/

    (function() {

        $.extend( $.effects, {
            version: "1.11.2",

            // saves a set of properties in a data storage
            save: function( element, set ) {
                for ( var i = 0; i < set.length; i++ ) {
                    if ( set[ i ] !== null ) {
                        element.data( dataspace + set[ i ], element[ 0 ].style[ set[ i ] ] );
                    }
                }
            },

            // restores a set of previously saved properties from a data storage
            restore: function( element, set ) {
                var val, i;
                for ( i = 0; i < set.length; i++ ) {
                    if ( set[ i ] !== null ) {
                        val = element.data( dataspace + set[ i ] );
                        // support: jquery 1.6.2
                        // http://bugs.jquery.com/ticket/9917
                        // jquery 1.6.2 incorrectly returns undefined for any falsy value.
                        // we can't differentiate between "" and 0 here, so we just assume
                        // empty string since it's likely to be a more common value...
                        if ( val === undefined ) {
                            val = "";
                        }
                        element.css( set[ i ], val );
                    }
                }
            },

            setmode: function( el, mode ) {
                if (mode === "toggle") {
                    mode = el.is( ":hidden" ) ? "show" : "hide";
                }
                return mode;
            },

            // translates a [top,left] array into a baseline value
            // this should be a little more flexible in the future to handle a string & hash
            getbaseline: function( origin, original ) {
                var y, x;
                switch ( origin[ 0 ] ) {
                    case "top": y = 0; break;
                    case "middle": y = 0.5; break;
                    case "bottom": y = 1; break;
                    default: y = origin[ 0 ] / original.height;
                }
                switch ( origin[ 1 ] ) {
                    case "left": x = 0; break;
                    case "center": x = 0.5; break;
                    case "right": x = 1; break;
                    default: x = origin[ 1 ] / original.width;
                }
                return {
                    x: x,
                    y: y
                };
            },

            // wraps the element around a wrapper that copies position properties
            createwrapper: function( element ) {

                // if the element is already wrapped, return it
                if ( element.parent().is( ".ui-effects-wrapper" )) {
                    return element.parent();
                }

                // wrap the element
                var props = {
                        width: element.outerwidth(true),
                        height: element.outerheight(true),
                        "float": element.css( "float" )
                    },
                    wrapper = $( "<div></div>" )
                        .addclass( "ui-effects-wrapper" )
                        .css({
                            fontsize: "100%",
                            background: "transparent",
                            border: "none",
                            margin: 0,
                            padding: 0
                        }),
                // store the size in case width/height are defined in % - fixes #5245
                    size = {
                        width: element.width(),
                        height: element.height()
                    },
                    active = document.activeelement;

                // support: firefox
                // firefox incorrectly exposes anonymous content
                // https://bugzilla.mozilla.org/show_bug.cgi?id=561664
                try {
                    active.id;
                } catch ( e ) {
                    active = document.body;
                }

                element.wrap( wrapper );

                // fixes #7595 - elements lose focus when wrapped.
                if ( element[ 0 ] === active || $.contains( element[ 0 ], active ) ) {
                    $( active ).focus();
                }

                wrapper = element.parent(); //hotfix for jquery 1.4 since some change in wrap() seems to actually lose the reference to the wrapped element

                // transfer positioning properties to the wrapper
                if ( element.css( "position" ) === "static" ) {
                    wrapper.css({ position: "relative" });
                    element.css({ position: "relative" });
                } else {
                    $.extend( props, {
                        position: element.css( "position" ),
                        zindex: element.css( "z-index" )
                    });
                    $.each([ "top", "left", "bottom", "right" ], function(i, pos) {
                        props[ pos ] = element.css( pos );
                        if ( isnan( parseint( props[ pos ], 10 ) ) ) {
                            props[ pos ] = "auto";
                        }
                    });
                    element.css({
                        position: "relative",
                        top: 0,
                        left: 0,
                        right: "auto",
                        bottom: "auto"
                    });
                }
                element.css(size);

                return wrapper.css( props ).show();
            },

            removewrapper: function( element ) {
                var active = document.activeelement;

                if ( element.parent().is( ".ui-effects-wrapper" ) ) {
                    element.parent().replacewith( element );

                    // fixes #7595 - elements lose focus when wrapped.
                    if ( element[ 0 ] === active || $.contains( element[ 0 ], active ) ) {
                        $( active ).focus();
                    }
                }

                return element;
            },

            settransition: function( element, list, factor, value ) {
                value = value || {};
                $.each( list, function( i, x ) {
                    var unit = element.cssunit( x );
                    if ( unit[ 0 ] > 0 ) {
                        value[ x ] = unit[ 0 ] * factor + unit[ 1 ];
                    }
                });
                return value;
            }
        });

// return an effect options object for the given parameters:
        function _normalizearguments( effect, options, speed, callback ) {

            // allow passing all options as the first parameter
            if ( $.isplainobject( effect ) ) {
                options = effect;
                effect = effect.effect;
            }

            // convert to an object
            effect = { effect: effect };

            // catch (effect, null, ...)
            if ( options == null ) {
                options = {};
            }

            // catch (effect, callback)
            if ( $.isfunction( options ) ) {
                callback = options;
                speed = null;
                options = {};
            }

            // catch (effect, speed, ?)
            if ( typeof options === "number" || $.fx.speeds[ options ] ) {
                callback = speed;
                speed = options;
                options = {};
            }

            // catch (effect, options, callback)
            if ( $.isfunction( speed ) ) {
                callback = speed;
                speed = null;
            }

            // add options to effect
            if ( options ) {
                $.extend( effect, options );
            }

            speed = speed || options.duration;
            effect.duration = $.fx.off ? 0 :
                    typeof speed === "number" ? speed :
                    speed in $.fx.speeds ? $.fx.speeds[ speed ] :
                $.fx.speeds._default;

            effect.complete = callback || options.complete;

            return effect;
        }

        function standardanimationoption( option ) {
            // valid standard speeds (nothing, number, named speed)
            if ( !option || typeof option === "number" || $.fx.speeds[ option ] ) {
                return true;
            }

            // invalid strings - treat as "normal" speed
            if ( typeof option === "string" && !$.effects.effect[ option ] ) {
                return true;
            }

            // complete callback
            if ( $.isfunction( option ) ) {
                return true;
            }

            // options hash (but not naming an effect)
            if ( typeof option === "object" && !option.effect ) {
                return true;
            }

            // didn't match any standard api
            return false;
        }

        $.fn.extend({
            effect: function( /* effect, options, speed, callback */ ) {
                var args = _normalizearguments.apply( this, arguments ),
                    mode = args.mode,
                    queue = args.queue,
                    effectmethod = $.effects.effect[ args.effect ];

                if ( $.fx.off || !effectmethod ) {
                    // delegate to the original method (e.g., .show()) if possible
                    if ( mode ) {
                        return this[ mode ]( args.duration, args.complete );
                    } else {
                        return this.each( function() {
                            if ( args.complete ) {
                                args.complete.call( this );
                            }
                        });
                    }
                }

                function run( next ) {
                    var elem = $( this ),
                        complete = args.complete,
                        mode = args.mode;

                    function done() {
                        if ( $.isfunction( complete ) ) {
                            complete.call( elem[0] );
                        }
                        if ( $.isfunction( next ) ) {
                            next();
                        }
                    }

                    // if the element already has the correct final state, delegate to
                    // the core methods so the internal tracking of "olddisplay" works.
                    if ( elem.is( ":hidden" ) ? mode === "hide" : mode === "show" ) {
                        elem[ mode ]();
                        done();
                    } else {
                        effectmethod.call( elem[0], args, done );
                    }
                }

                return queue === false ? this.each( run ) : this.queue( queue || "fx", run );
            },

            show: (function( orig ) {
                return function( option ) {
                    if ( standardanimationoption( option ) ) {
                        return orig.apply( this, arguments );
                    } else {
                        var args = _normalizearguments.apply( this, arguments );
                        args.mode = "show";
                        return this.effect.call( this, args );
                    }
                };
            })( $.fn.show ),

            hide: (function( orig ) {
                return function( option ) {
                    if ( standardanimationoption( option ) ) {
                        return orig.apply( this, arguments );
                    } else {
                        var args = _normalizearguments.apply( this, arguments );
                        args.mode = "hide";
                        return this.effect.call( this, args );
                    }
                };
            })( $.fn.hide ),

            toggle: (function( orig ) {
                return function( option ) {
                    if ( standardanimationoption( option ) || typeof option === "boolean" ) {
                        return orig.apply( this, arguments );
                    } else {
                        var args = _normalizearguments.apply( this, arguments );
                        args.mode = "toggle";
                        return this.effect.call( this, args );
                    }
                };
            })( $.fn.toggle ),

            // helper functions
            cssunit: function(key) {
                var style = this.css( key ),
                    val = [];

                $.each( [ "em", "px", "%", "pt" ], function( i, unit ) {
                    if ( style.indexof( unit ) > 0 ) {
                        val = [ parsefloat( style ), unit ];
                    }
                });
                return val;
            }
        });

    })();

    /******************************************************************************/
    /*********************************** easing ***********************************/
    /******************************************************************************/

    (function() {

// based on easing equations from robert penner (http://www.robertpenner.com/easing)

        var baseeasings = {};

        $.each( [ "quad", "cubic", "quart", "quint", "expo" ], function( i, name ) {
            baseeasings[ name ] = function( p ) {
                return math.pow( p, i + 2 );
            };
        });

        $.extend( baseeasings, {
            sine: function( p ) {
                return 1 - math.cos( p * math.pi / 2 );
            },
            circ: function( p ) {
                return 1 - math.sqrt( 1 - p * p );
            },
            elastic: function( p ) {
                return p === 0 || p === 1 ? p :
                    -math.pow( 2, 8 * (p - 1) ) * math.sin( ( (p - 1) * 80 - 7.5 ) * math.pi / 15 );
            },
            back: function( p ) {
                return p * p * ( 3 * p - 2 );
            },
            bounce: function( p ) {
                var pow2,
                    bounce = 4;

                while ( p < ( ( pow2 = math.pow( 2, --bounce ) ) - 1 ) / 11 ) {}
                return 1 / math.pow( 4, 3 - bounce ) - 7.5625 * math.pow( ( pow2 * 3 - 2 ) / 22 - p, 2 );
            }
        });

        $.each( baseeasings, function( name, easein ) {
            $.easing[ "easein" + name ] = easein;
            $.easing[ "easeout" + name ] = function( p ) {
                return 1 - easein( 1 - p );
            };
            $.easing[ "easeinout" + name ] = function( p ) {
                return p < 0.5 ?
                    easein( p * 2 ) / 2 :
                    1 - easein( p * -2 + 2 ) / 2;
            };
        });

    })();

    var effect = $.effects;


    /*!
     * jquery ui effects blind 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/blind-effect/
     */


    var effectblind = $.effects.effect.blind = function( o, done ) {
        // create element
        var el = $( this ),
            rvertical = /up|down|vertical/,
            rpositivemotion = /up|left|vertical|horizontal/,
            props = [ "position", "top", "bottom", "left", "right", "height", "width" ],
            mode = $.effects.setmode( el, o.mode || "hide" ),
            direction = o.direction || "up",
            vertical = rvertical.test( direction ),
            ref = vertical ? "height" : "width",
            ref2 = vertical ? "top" : "left",
            motion = rpositivemotion.test( direction ),
            animation = {},
            show = mode === "show",
            wrapper, distance, margin;

        // if already wrapped, the wrapper's properties are my property. #6245
        if ( el.parent().is( ".ui-effects-wrapper" ) ) {
            $.effects.save( el.parent(), props );
        } else {
            $.effects.save( el, props );
        }
        el.show();
        wrapper = $.effects.createwrapper( el ).css({
            overflow: "hidden"
        });

        distance = wrapper[ ref ]();
        margin = parsefloat( wrapper.css( ref2 ) ) || 0;

        animation[ ref ] = show ? distance : 0;
        if ( !motion ) {
            el
                .css( vertical ? "bottom" : "right", 0 )
                .css( vertical ? "top" : "left", "auto" )
                .css({ position: "absolute" });

            animation[ ref2 ] = show ? margin : distance + margin;
        }

        // start at 0 if we are showing
        if ( show ) {
            wrapper.css( ref, 0 );
            if ( !motion ) {
                wrapper.css( ref2, margin + distance );
            }
        }

        // animate
        wrapper.animate( animation, {
            duration: o.duration,
            easing: o.easing,
            queue: false,
            complete: function() {
                if ( mode === "hide" ) {
                    el.hide();
                }
                $.effects.restore( el, props );
                $.effects.removewrapper( el );
                done();
            }
        });
    };


    /*!
     * jquery ui effects bounce 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/bounce-effect/
     */


    var effectbounce = $.effects.effect.bounce = function( o, done ) {
        var el = $( this ),
            props = [ "position", "top", "bottom", "left", "right", "height", "width" ],

        // defaults:
            mode = $.effects.setmode( el, o.mode || "effect" ),
            hide = mode === "hide",
            show = mode === "show",
            direction = o.direction || "up",
            distance = o.distance,
            times = o.times || 5,

        // number of internal animations
            anims = times * 2 + ( show || hide ? 1 : 0 ),
            speed = o.duration / anims,
            easing = o.easing,

        // utility:
            ref = ( direction === "up" || direction === "down" ) ? "top" : "left",
            motion = ( direction === "up" || direction === "left" ),
            i,
            upanim,
            downanim,

        // we will need to re-assemble the queue to stack our animations in place
            queue = el.queue(),
            queuelen = queue.length;

        // avoid touching opacity to prevent cleartype and png issues in ie
        if ( show || hide ) {
            props.push( "opacity" );
        }

        $.effects.save( el, props );
        el.show();
        $.effects.createwrapper( el ); // create wrapper

        // default distance for the biggest bounce is the outer distance / 3
        if ( !distance ) {
            distance = el[ ref === "top" ? "outerheight" : "outerwidth" ]() / 3;
        }

        if ( show ) {
            downanim = { opacity: 1 };
            downanim[ ref ] = 0;

            // if we are showing, force opacity 0 and set the initial position
            // then do the "first" animation
            el.css( "opacity", 0 )
                .css( ref, motion ? -distance * 2 : distance * 2 )
                .animate( downanim, speed, easing );
        }

        // start at the smallest distance if we are hiding
        if ( hide ) {
            distance = distance / math.pow( 2, times - 1 );
        }

        downanim = {};
        downanim[ ref ] = 0;
        // bounces up/down/left/right then back to 0 -- times * 2 animations happen here
        for ( i = 0; i < times; i++ ) {
            upanim = {};
            upanim[ ref ] = ( motion ? "-=" : "+=" ) + distance;

            el.animate( upanim, speed, easing )
                .animate( downanim, speed, easing );

            distance = hide ? distance * 2 : distance / 2;
        }

        // last bounce when hiding
        if ( hide ) {
            upanim = { opacity: 0 };
            upanim[ ref ] = ( motion ? "-=" : "+=" ) + distance;

            el.animate( upanim, speed, easing );
        }

        el.queue(function() {
            if ( hide ) {
                el.hide();
            }
            $.effects.restore( el, props );
            $.effects.removewrapper( el );
            done();
        });

        // inject all the animations we just queued to be first in line (after "inprogress")
        if ( queuelen > 1) {
            queue.splice.apply( queue,
                [ 1, 0 ].concat( queue.splice( queuelen, anims + 1 ) ) );
        }
        el.dequeue();

    };


    /*!
     * jquery ui effects clip 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/clip-effect/
     */


    var effectclip = $.effects.effect.clip = function( o, done ) {
        // create element
        var el = $( this ),
            props = [ "position", "top", "bottom", "left", "right", "height", "width" ],
            mode = $.effects.setmode( el, o.mode || "hide" ),
            show = mode === "show",
            direction = o.direction || "vertical",
            vert = direction === "vertical",
            size = vert ? "height" : "width",
            position = vert ? "top" : "left",
            animation = {},
            wrapper, animate, distance;

        // save & show
        $.effects.save( el, props );
        el.show();

        // create wrapper
        wrapper = $.effects.createwrapper( el ).css({
            overflow: "hidden"
        });
        animate = ( el[0].tagname === "img" ) ? wrapper : el;
        distance = animate[ size ]();

        // shift
        if ( show ) {
            animate.css( size, 0 );
            animate.css( position, distance / 2 );
        }

        // create animation object:
        animation[ size ] = show ? distance : 0;
        animation[ position ] = show ? 0 : distance / 2;

        // animate
        animate.animate( animation, {
            queue: false,
            duration: o.duration,
            easing: o.easing,
            complete: function() {
                if ( !show ) {
                    el.hide();
                }
                $.effects.restore( el, props );
                $.effects.removewrapper( el );
                done();
            }
        });

    };


    /*!
     * jquery ui effects drop 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/drop-effect/
     */


    var effectdrop = $.effects.effect.drop = function( o, done ) {

        var el = $( this ),
            props = [ "position", "top", "bottom", "left", "right", "opacity", "height", "width" ],
            mode = $.effects.setmode( el, o.mode || "hide" ),
            show = mode === "show",
            direction = o.direction || "left",
            ref = ( direction === "up" || direction === "down" ) ? "top" : "left",
            motion = ( direction === "up" || direction === "left" ) ? "pos" : "neg",
            animation = {
                opacity: show ? 1 : 0
            },
            distance;

        // adjust
        $.effects.save( el, props );
        el.show();
        $.effects.createwrapper( el );

        distance = o.distance || el[ ref === "top" ? "outerheight" : "outerwidth" ]( true ) / 2;

        if ( show ) {
            el
                .css( "opacity", 0 )
                .css( ref, motion === "pos" ? -distance : distance );
        }

        // animation
        animation[ ref ] = ( show ?
            ( motion === "pos" ? "+=" : "-=" ) :
            ( motion === "pos" ? "-=" : "+=" ) ) +
            distance;

        // animate
        el.animate( animation, {
            queue: false,
            duration: o.duration,
            easing: o.easing,
            complete: function() {
                if ( mode === "hide" ) {
                    el.hide();
                }
                $.effects.restore( el, props );
                $.effects.removewrapper( el );
                done();
            }
        });
    };


    /*!
     * jquery ui effects explode 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/explode-effect/
     */


    var effectexplode = $.effects.effect.explode = function( o, done ) {

        var rows = o.pieces ? math.round( math.sqrt( o.pieces ) ) : 3,
            cells = rows,
            el = $( this ),
            mode = $.effects.setmode( el, o.mode || "hide" ),
            show = mode === "show",

        // show and then visibility:hidden the element before calculating offset
            offset = el.show().css( "visibility", "hidden" ).offset(),

        // width and height of a piece
            width = math.ceil( el.outerwidth() / cells ),
            height = math.ceil( el.outerheight() / rows ),
            pieces = [],

        // loop
            i, j, left, top, mx, my;

        // children animate complete:
        function childcomplete() {
            pieces.push( this );
            if ( pieces.length === rows * cells ) {
                animcomplete();
            }
        }

        // clone the element for each row and cell.
        for ( i = 0; i < rows ; i++ ) { // ===>
            top = offset.top + i * height;
            my = i - ( rows - 1 ) / 2 ;

            for ( j = 0; j < cells ; j++ ) { // |||
                left = offset.left + j * width;
                mx = j - ( cells - 1 ) / 2 ;

                // create a clone of the now hidden main element that will be absolute positioned
                // within a wrapper div off the -left and -top equal to size of our pieces
                el
                    .clone()
                    .appendto( "body" )
                    .wrap( "<div></div>" )
                    .css({
                        position: "absolute",
                        visibility: "visible",
                        left: -j * width,
                        top: -i * height
                    })

                    // select the wrapper - make it overflow: hidden and absolute positioned based on
                    // where the original was located +left and +top equal to the size of pieces
                    .parent()
                    .addclass( "ui-effects-explode" )
                    .css({
                        position: "absolute",
                        overflow: "hidden",
                        width: width,
                        height: height,
                        left: left + ( show ? mx * width : 0 ),
                        top: top + ( show ? my * height : 0 ),
                        opacity: show ? 0 : 1
                    }).animate({
                        left: left + ( show ? 0 : mx * width ),
                        top: top + ( show ? 0 : my * height ),
                        opacity: show ? 1 : 0
                    }, o.duration || 500, o.easing, childcomplete );
            }
        }

        function animcomplete() {
            el.css({
                visibility: "visible"
            });
            $( pieces ).remove();
            if ( !show ) {
                el.hide();
            }
            done();
        }
    };


    /*!
     * jquery ui effects fade 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/fade-effect/
     */


    var effectfade = $.effects.effect.fade = function( o, done ) {
        var el = $( this ),
            mode = $.effects.setmode( el, o.mode || "toggle" );

        el.animate({
            opacity: mode
        }, {
            queue: false,
            duration: o.duration,
            easing: o.easing,
            complete: done
        });
    };


    /*!
     * jquery ui effects fold 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/fold-effect/
     */


    var effectfold = $.effects.effect.fold = function( o, done ) {

        // create element
        var el = $( this ),
            props = [ "position", "top", "bottom", "left", "right", "height", "width" ],
            mode = $.effects.setmode( el, o.mode || "hide" ),
            show = mode === "show",
            hide = mode === "hide",
            size = o.size || 15,
            percent = /([0-9]+)%/.exec( size ),
            horizfirst = !!o.horizfirst,
            widthfirst = show !== horizfirst,
            ref = widthfirst ? [ "width", "height" ] : [ "height", "width" ],
            duration = o.duration / 2,
            wrapper, distance,
            animation1 = {},
            animation2 = {};

        $.effects.save( el, props );
        el.show();

        // create wrapper
        wrapper = $.effects.createwrapper( el ).css({
            overflow: "hidden"
        });
        distance = widthfirst ?
            [ wrapper.width(), wrapper.height() ] :
            [ wrapper.height(), wrapper.width() ];

        if ( percent ) {
            size = parseint( percent[ 1 ], 10 ) / 100 * distance[ hide ? 0 : 1 ];
        }
        if ( show ) {
            wrapper.css( horizfirst ? {
                height: 0,
                width: size
            } : {
                height: size,
                width: 0
            });
        }

        // animation
        animation1[ ref[ 0 ] ] = show ? distance[ 0 ] : size;
        animation2[ ref[ 1 ] ] = show ? distance[ 1 ] : 0;

        // animate
        wrapper
            .animate( animation1, duration, o.easing )
            .animate( animation2, duration, o.easing, function() {
                if ( hide ) {
                    el.hide();
                }
                $.effects.restore( el, props );
                $.effects.removewrapper( el );
                done();
            });

    };


    /*!
     * jquery ui effects highlight 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/highlight-effect/
     */


    var effecthighlight = $.effects.effect.highlight = function( o, done ) {
        var elem = $( this ),
            props = [ "backgroundimage", "backgroundcolor", "opacity" ],
            mode = $.effects.setmode( elem, o.mode || "show" ),
            animation = {
                backgroundcolor: elem.css( "backgroundcolor" )
            };

        if (mode === "hide") {
            animation.opacity = 0;
        }

        $.effects.save( elem, props );

        elem
            .show()
            .css({
                backgroundimage: "none",
                backgroundcolor: o.color || "#ffff99"
            })
            .animate( animation, {
                queue: false,
                duration: o.duration,
                easing: o.easing,
                complete: function() {
                    if ( mode === "hide" ) {
                        elem.hide();
                    }
                    $.effects.restore( elem, props );
                    done();
                }
            });
    };


    /*!
     * jquery ui effects size 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/size-effect/
     */


    var effectsize = $.effects.effect.size = function( o, done ) {

        // create element
        var original, baseline, factor,
            el = $( this ),
            props0 = [ "position", "top", "bottom", "left", "right", "width", "height", "overflow", "opacity" ],

        // always restore
            props1 = [ "position", "top", "bottom", "left", "right", "overflow", "opacity" ],

        // copy for children
            props2 = [ "width", "height", "overflow" ],
            cprops = [ "fontsize" ],
            vprops = [ "bordertopwidth", "borderbottomwidth", "paddingtop", "paddingbottom" ],
            hprops = [ "borderleftwidth", "borderrightwidth", "paddingleft", "paddingright" ],

        // set options
            mode = $.effects.setmode( el, o.mode || "effect" ),
            restore = o.restore || mode !== "effect",
            scale = o.scale || "both",
            origin = o.origin || [ "middle", "center" ],
            position = el.css( "position" ),
            props = restore ? props0 : props1,
            zero = {
                height: 0,
                width: 0,
                outerheight: 0,
                outerwidth: 0
            };

        if ( mode === "show" ) {
            el.show();
        }
        original = {
            height: el.height(),
            width: el.width(),
            outerheight: el.outerheight(),
            outerwidth: el.outerwidth()
        };

        if ( o.mode === "toggle" && mode === "show" ) {
            el.from = o.to || zero;
            el.to = o.from || original;
        } else {
            el.from = o.from || ( mode === "show" ? zero : original );
            el.to = o.to || ( mode === "hide" ? zero : original );
        }

        // set scaling factor
        factor = {
            from: {
                y: el.from.height / original.height,
                x: el.from.width / original.width
            },
            to: {
                y: el.to.height / original.height,
                x: el.to.width / original.width
            }
        };

        // scale the css box
        if ( scale === "box" || scale === "both" ) {

            // vertical props scaling
            if ( factor.from.y !== factor.to.y ) {
                props = props.concat( vprops );
                el.from = $.effects.settransition( el, vprops, factor.from.y, el.from );
                el.to = $.effects.settransition( el, vprops, factor.to.y, el.to );
            }

            // horizontal props scaling
            if ( factor.from.x !== factor.to.x ) {
                props = props.concat( hprops );
                el.from = $.effects.settransition( el, hprops, factor.from.x, el.from );
                el.to = $.effects.settransition( el, hprops, factor.to.x, el.to );
            }
        }

        // scale the content
        if ( scale === "content" || scale === "both" ) {

            // vertical props scaling
            if ( factor.from.y !== factor.to.y ) {
                props = props.concat( cprops ).concat( props2 );
                el.from = $.effects.settransition( el, cprops, factor.from.y, el.from );
                el.to = $.effects.settransition( el, cprops, factor.to.y, el.to );
            }
        }

        $.effects.save( el, props );
        el.show();
        $.effects.createwrapper( el );
        el.css( "overflow", "hidden" ).css( el.from );

        // adjust
        if (origin) { // calculate baseline shifts
            baseline = $.effects.getbaseline( origin, original );
            el.from.top = ( original.outerheight - el.outerheight() ) * baseline.y;
            el.from.left = ( original.outerwidth - el.outerwidth() ) * baseline.x;
            el.to.top = ( original.outerheight - el.to.outerheight ) * baseline.y;
            el.to.left = ( original.outerwidth - el.to.outerwidth ) * baseline.x;
        }
        el.css( el.from ); // set top & left

        // animate
        if ( scale === "content" || scale === "both" ) { // scale the children

            // add margins/font-size
            vprops = vprops.concat([ "margintop", "marginbottom" ]).concat(cprops);
            hprops = hprops.concat([ "marginleft", "marginright" ]);
            props2 = props0.concat(vprops).concat(hprops);

            el.find( "*[width]" ).each( function() {
                var child = $( this ),
                    c_original = {
                        height: child.height(),
                        width: child.width(),
                        outerheight: child.outerheight(),
                        outerwidth: child.outerwidth()
                    };
                if (restore) {
                    $.effects.save(child, props2);
                }

                child.from = {
                    height: c_original.height * factor.from.y,
                    width: c_original.width * factor.from.x,
                    outerheight: c_original.outerheight * factor.from.y,
                    outerwidth: c_original.outerwidth * factor.from.x
                };
                child.to = {
                    height: c_original.height * factor.to.y,
                    width: c_original.width * factor.to.x,
                    outerheight: c_original.height * factor.to.y,
                    outerwidth: c_original.width * factor.to.x
                };

                // vertical props scaling
                if ( factor.from.y !== factor.to.y ) {
                    child.from = $.effects.settransition( child, vprops, factor.from.y, child.from );
                    child.to = $.effects.settransition( child, vprops, factor.to.y, child.to );
                }

                // horizontal props scaling
                if ( factor.from.x !== factor.to.x ) {
                    child.from = $.effects.settransition( child, hprops, factor.from.x, child.from );
                    child.to = $.effects.settransition( child, hprops, factor.to.x, child.to );
                }

                // animate children
                child.css( child.from );
                child.animate( child.to, o.duration, o.easing, function() {

                    // restore children
                    if ( restore ) {
                        $.effects.restore( child, props2 );
                    }
                });
            });
        }

        // animate
        el.animate( el.to, {
            queue: false,
            duration: o.duration,
            easing: o.easing,
            complete: function() {
                if ( el.to.opacity === 0 ) {
                    el.css( "opacity", el.from.opacity );
                }
                if ( mode === "hide" ) {
                    el.hide();
                }
                $.effects.restore( el, props );
                if ( !restore ) {

                    // we need to calculate our new positioning based on the scaling
                    if ( position === "static" ) {
                        el.css({
                            position: "relative",
                            top: el.to.top,
                            left: el.to.left
                        });
                    } else {
                        $.each([ "top", "left" ], function( idx, pos ) {
                            el.css( pos, function( _, str ) {
                                var val = parseint( str, 10 ),
                                    toref = idx ? el.to.left : el.to.top;

                                // if original was "auto", recalculate the new value from wrapper
                                if ( str === "auto" ) {
                                    return toref + "px";
                                }

                                return val + toref + "px";
                            });
                        });
                    }
                }

                $.effects.removewrapper( el );
                done();
            }
        });

    };


    /*!
     * jquery ui effects scale 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/scale-effect/
     */


    var effectscale = $.effects.effect.scale = function( o, done ) {

        // create element
        var el = $( this ),
            options = $.extend( true, {}, o ),
            mode = $.effects.setmode( el, o.mode || "effect" ),
            percent = parseint( o.percent, 10 ) ||
                ( parseint( o.percent, 10 ) === 0 ? 0 : ( mode === "hide" ? 0 : 100 ) ),
            direction = o.direction || "both",
            origin = o.origin,
            original = {
                height: el.height(),
                width: el.width(),
                outerheight: el.outerheight(),
                outerwidth: el.outerwidth()
            },
            factor = {
                y: direction !== "horizontal" ? (percent / 100) : 1,
                x: direction !== "vertical" ? (percent / 100) : 1
            };

        // we are going to pass this effect to the size effect:
        options.effect = "size";
        options.queue = false;
        options.complete = done;

        // set default origin and restore for show/hide
        if ( mode !== "effect" ) {
            options.origin = origin || [ "middle", "center" ];
            options.restore = true;
        }

        options.from = o.from || ( mode === "show" ? {
            height: 0,
            width: 0,
            outerheight: 0,
            outerwidth: 0
        } : original );
        options.to = {
            height: original.height * factor.y,
            width: original.width * factor.x,
            outerheight: original.outerheight * factor.y,
            outerwidth: original.outerwidth * factor.x
        };

        // fade option to support puff
        if ( options.fade ) {
            if ( mode === "show" ) {
                options.from.opacity = 0;
                options.to.opacity = 1;
            }
            if ( mode === "hide" ) {
                options.from.opacity = 1;
                options.to.opacity = 0;
            }
        }

        // animate
        el.effect( options );

    };


    /*!
     * jquery ui effects puff 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/puff-effect/
     */


    var effectpuff = $.effects.effect.puff = function( o, done ) {
        var elem = $( this ),
            mode = $.effects.setmode( elem, o.mode || "hide" ),
            hide = mode === "hide",
            percent = parseint( o.percent, 10 ) || 150,
            factor = percent / 100,
            original = {
                height: elem.height(),
                width: elem.width(),
                outerheight: elem.outerheight(),
                outerwidth: elem.outerwidth()
            };

        $.extend( o, {
            effect: "scale",
            queue: false,
            fade: true,
            mode: mode,
            complete: done,
            percent: hide ? percent : 100,
            from: hide ?
                original :
            {
                height: original.height * factor,
                width: original.width * factor,
                outerheight: original.outerheight * factor,
                outerwidth: original.outerwidth * factor
            }
        });

        elem.effect( o );
    };


    /*!
     * jquery ui effects pulsate 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/pulsate-effect/
     */


    var effectpulsate = $.effects.effect.pulsate = function( o, done ) {
        var elem = $( this ),
            mode = $.effects.setmode( elem, o.mode || "show" ),
            show = mode === "show",
            hide = mode === "hide",
            showhide = ( show || mode === "hide" ),

        // showing or hiding leaves of the "last" animation
            anims = ( ( o.times || 5 ) * 2 ) + ( showhide ? 1 : 0 ),
            duration = o.duration / anims,
            animateto = 0,
            queue = elem.queue(),
            queuelen = queue.length,
            i;

        if ( show || !elem.is(":visible")) {
            elem.css( "opacity", 0 ).show();
            animateto = 1;
        }

        // anims - 1 opacity "toggles"
        for ( i = 1; i < anims; i++ ) {
            elem.animate({
                opacity: animateto
            }, duration, o.easing );
            animateto = 1 - animateto;
        }

        elem.animate({
            opacity: animateto
        }, duration, o.easing);

        elem.queue(function() {
            if ( hide ) {
                elem.hide();
            }
            done();
        });

        // we just queued up "anims" animations, we need to put them next in the queue
        if ( queuelen > 1 ) {
            queue.splice.apply( queue,
                [ 1, 0 ].concat( queue.splice( queuelen, anims + 1 ) ) );
        }
        elem.dequeue();
    };


    /*!
     * jquery ui effects shake 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/shake-effect/
     */


    var effectshake = $.effects.effect.shake = function( o, done ) {

        var el = $( this ),
            props = [ "position", "top", "bottom", "left", "right", "height", "width" ],
            mode = $.effects.setmode( el, o.mode || "effect" ),
            direction = o.direction || "left",
            distance = o.distance || 20,
            times = o.times || 3,
            anims = times * 2 + 1,
            speed = math.round( o.duration / anims ),
            ref = (direction === "up" || direction === "down") ? "top" : "left",
            positivemotion = (direction === "up" || direction === "left"),
            animation = {},
            animation1 = {},
            animation2 = {},
            i,

        // we will need to re-assemble the queue to stack our animations in place
            queue = el.queue(),
            queuelen = queue.length;

        $.effects.save( el, props );
        el.show();
        $.effects.createwrapper( el );

        // animation
        animation[ ref ] = ( positivemotion ? "-=" : "+=" ) + distance;
        animation1[ ref ] = ( positivemotion ? "+=" : "-=" ) + distance * 2;
        animation2[ ref ] = ( positivemotion ? "-=" : "+=" ) + distance * 2;

        // animate
        el.animate( animation, speed, o.easing );

        // shakes
        for ( i = 1; i < times; i++ ) {
            el.animate( animation1, speed, o.easing ).animate( animation2, speed, o.easing );
        }
        el
            .animate( animation1, speed, o.easing )
            .animate( animation, speed / 2, o.easing )
            .queue(function() {
                if ( mode === "hide" ) {
                    el.hide();
                }
                $.effects.restore( el, props );
                $.effects.removewrapper( el );
                done();
            });

        // inject all the animations we just queued to be first in line (after "inprogress")
        if ( queuelen > 1) {
            queue.splice.apply( queue,
                [ 1, 0 ].concat( queue.splice( queuelen, anims + 1 ) ) );
        }
        el.dequeue();

    };


    /*!
     * jquery ui effects slide 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/slide-effect/
     */


    var effectslide = $.effects.effect.slide = function( o, done ) {

        // create element
        var el = $( this ),
            props = [ "position", "top", "bottom", "left", "right", "width", "height" ],
            mode = $.effects.setmode( el, o.mode || "show" ),
            show = mode === "show",
            direction = o.direction || "left",
            ref = (direction === "up" || direction === "down") ? "top" : "left",
            positivemotion = (direction === "up" || direction === "left"),
            distance,
            animation = {};

        // adjust
        $.effects.save( el, props );
        el.show();
        distance = o.distance || el[ ref === "top" ? "outerheight" : "outerwidth" ]( true );

        $.effects.createwrapper( el ).css({
            overflow: "hidden"
        });

        if ( show ) {
            el.css( ref, positivemotion ? (isnan(distance) ? "-" + distance : -distance) : distance );
        }

        // animation
        animation[ ref ] = ( show ?
            ( positivemotion ? "+=" : "-=") :
            ( positivemotion ? "-=" : "+=")) +
            distance;

        // animate
        el.animate( animation, {
            queue: false,
            duration: o.duration,
            easing: o.easing,
            complete: function() {
                if ( mode === "hide" ) {
                    el.hide();
                }
                $.effects.restore( el, props );
                $.effects.removewrapper( el );
                done();
            }
        });
    };


    /*!
     * jquery ui effects transfer 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/transfer-effect/
     */


    var effecttransfer = $.effects.effect.transfer = function( o, done ) {
        var elem = $( this ),
            target = $( o.to ),
            targetfixed = target.css( "position" ) === "fixed",
            body = $("body"),
            fixtop = targetfixed ? body.scrolltop() : 0,
            fixleft = targetfixed ? body.scrollleft() : 0,
            endposition = target.offset(),
            animation = {
                top: endposition.top - fixtop,
                left: endposition.left - fixleft,
                height: target.innerheight(),
                width: target.innerwidth()
            },
            startposition = elem.offset(),
            transfer = $( "<div class='ui-effects-transfer'></div>" )
                .appendto( document.body )
                .addclass( o.classname )
                .css({
                    top: startposition.top - fixtop,
                    left: startposition.left - fixleft,
                    height: elem.innerheight(),
                    width: elem.innerwidth(),
                    position: targetfixed ? "fixed" : "absolute"
                })
                .animate( animation, o.duration, o.easing, function() {
                    transfer.remove();
                    done();
                });
    };


    /*!
     * jquery ui progressbar 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/progressbar/
     */


    var progressbar = $.widget( "ui.progressbar", {
        version: "1.11.2",
        options: {
            max: 100,
            value: 0,

            change: null,
            complete: null
        },

        min: 0,

        _create: function() {
            // constrain initial value
            this.oldvalue = this.options.value = this._constrainedvalue();

            this.element
                .addclass( "ui-progressbar ui-widget ui-widget-content ui-corner-all" )
                .attr({
                    // only set static values, aria-valuenow and aria-valuemax are
                    // set inside _refreshvalue()
                    role: "progressbar",
                    "aria-valuemin": this.min
                });

            this.valuediv = $( "<div class='ui-progressbar-value ui-widget-header ui-corner-left'></div>" )
                .appendto( this.element );

            this._refreshvalue();
        },

        _destroy: function() {
            this.element
                .removeclass( "ui-progressbar ui-widget ui-widget-content ui-corner-all" )
                .removeattr( "role" )
                .removeattr( "aria-valuemin" )
                .removeattr( "aria-valuemax" )
                .removeattr( "aria-valuenow" );

            this.valuediv.remove();
        },

        value: function( newvalue ) {
            if ( newvalue === undefined ) {
                return this.options.value;
            }

            this.options.value = this._constrainedvalue( newvalue );
            this._refreshvalue();
        },

        _constrainedvalue: function( newvalue ) {
            if ( newvalue === undefined ) {
                newvalue = this.options.value;
            }

            this.indeterminate = newvalue === false;

            // sanitize value
            if ( typeof newvalue !== "number" ) {
                newvalue = 0;
            }

            return this.indeterminate ? false :
                math.min( this.options.max, math.max( this.min, newvalue ) );
        },

        _setoptions: function( options ) {
            // ensure "value" option is set after other values (like max)
            var value = options.value;
            delete options.value;

            this._super( options );

            this.options.value = this._constrainedvalue( value );
            this._refreshvalue();
        },

        _setoption: function( key, value ) {
            if ( key === "max" ) {
                // don't allow a max less than min
                value = math.max( this.min, value );
            }
            if ( key === "disabled" ) {
                this.element
                    .toggleclass( "ui-state-disabled", !!value )
                    .attr( "aria-disabled", value );
            }
            this._super( key, value );
        },

        _percentage: function() {
            return this.indeterminate ? 100 : 100 * ( this.options.value - this.min ) / ( this.options.max - this.min );
        },

        _refreshvalue: function() {
            var value = this.options.value,
                percentage = this._percentage();

            this.valuediv
                .toggle( this.indeterminate || value > this.min )
                .toggleclass( "ui-corner-right", value === this.options.max )
                .width( percentage.tofixed(0) + "%" );

            this.element.toggleclass( "ui-progressbar-indeterminate", this.indeterminate );

            if ( this.indeterminate ) {
                this.element.removeattr( "aria-valuenow" );
                if ( !this.overlaydiv ) {
                    this.overlaydiv = $( "<div class='ui-progressbar-overlay'></div>" ).appendto( this.valuediv );
                }
            } else {
                this.element.attr({
                    "aria-valuemax": this.options.max,
                    "aria-valuenow": value
                });
                if ( this.overlaydiv ) {
                    this.overlaydiv.remove();
                    this.overlaydiv = null;
                }
            }

            if ( this.oldvalue !== value ) {
                this.oldvalue = value;
                this._trigger( "change" );
            }
            if ( value === this.options.max ) {
                this._trigger( "complete" );
            }
        }
    });


    /*!
     * jquery ui selectable 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/selectable/
     */


    var selectable = $.widget("ui.selectable", $.ui.mouse, {
        version: "1.11.2",
        options: {
            appendto: "body",
            autorefresh: true,
            distance: 0,
            filter: "*",
            tolerance: "touch",

            // callbacks
            selected: null,
            selecting: null,
            start: null,
            stop: null,
            unselected: null,
            unselecting: null
        },
        _create: function() {
            var selectees,
                that = this;

            this.element.addclass("ui-selectable");

            this.dragged = false;

            // cache selectee children based on filter
            this.refresh = function() {
                selectees = $(that.options.filter, that.element[0]);
                selectees.addclass("ui-selectee");
                selectees.each(function() {
                    var $this = $(this),
                        pos = $this.offset();
                    $.data(this, "selectable-item", {
                        element: this,
                        $element: $this,
                        left: pos.left,
                        top: pos.top,
                        right: pos.left + $this.outerwidth(),
                        bottom: pos.top + $this.outerheight(),
                        startselected: false,
                        selected: $this.hasclass("ui-selected"),
                        selecting: $this.hasclass("ui-selecting"),
                        unselecting: $this.hasclass("ui-unselecting")
                    });
                });
            };
            this.refresh();

            this.selectees = selectees.addclass("ui-selectee");

            this._mouseinit();

            this.helper = $("<div class='ui-selectable-helper'></div>");
        },

        _destroy: function() {
            this.selectees
                .removeclass("ui-selectee")
                .removedata("selectable-item");
            this.element
                .removeclass("ui-selectable ui-selectable-disabled");
            this._mousedestroy();
        },

        _mousestart: function(event) {
            var that = this,
                options = this.options;

            this.opos = [ event.pagex, event.pagey ];

            if (this.options.disabled) {
                return;
            }

            this.selectees = $(options.filter, this.element[0]);

            this._trigger("start", event);

            $(options.appendto).append(this.helper);
            // position helper (lasso)
            this.helper.css({
                "left": event.pagex,
                "top": event.pagey,
                "width": 0,
                "height": 0
            });

            if (options.autorefresh) {
                this.refresh();
            }

            this.selectees.filter(".ui-selected").each(function() {
                var selectee = $.data(this, "selectable-item");
                selectee.startselected = true;
                if (!event.metakey && !event.ctrlkey) {
                    selectee.$element.removeclass("ui-selected");
                    selectee.selected = false;
                    selectee.$element.addclass("ui-unselecting");
                    selectee.unselecting = true;
                    // selectable unselecting callback
                    that._trigger("unselecting", event, {
                        unselecting: selectee.element
                    });
                }
            });

            $(event.target).parents().addback().each(function() {
                var doselect,
                    selectee = $.data(this, "selectable-item");
                if (selectee) {
                    doselect = (!event.metakey && !event.ctrlkey) || !selectee.$element.hasclass("ui-selected");
                    selectee.$element
                        .removeclass(doselect ? "ui-unselecting" : "ui-selected")
                        .addclass(doselect ? "ui-selecting" : "ui-unselecting");
                    selectee.unselecting = !doselect;
                    selectee.selecting = doselect;
                    selectee.selected = doselect;
                    // selectable (un)selecting callback
                    if (doselect) {
                        that._trigger("selecting", event, {
                            selecting: selectee.element
                        });
                    } else {
                        that._trigger("unselecting", event, {
                            unselecting: selectee.element
                        });
                    }
                    return false;
                }
            });

        },

        _mousedrag: function(event) {

            this.dragged = true;

            if (this.options.disabled) {
                return;
            }

            var tmp,
                that = this,
                options = this.options,
                x1 = this.opos[0],
                y1 = this.opos[1],
                x2 = event.pagex,
                y2 = event.pagey;

            if (x1 > x2) { tmp = x2; x2 = x1; x1 = tmp; }
            if (y1 > y2) { tmp = y2; y2 = y1; y1 = tmp; }
            this.helper.css({ left: x1, top: y1, width: x2 - x1, height: y2 - y1 });

            this.selectees.each(function() {
                var selectee = $.data(this, "selectable-item"),
                    hit = false;

                //prevent helper from being selected if appendto: selectable
                if (!selectee || selectee.element === that.element[0]) {
                    return;
                }

                if (options.tolerance === "touch") {
                    hit = ( !(selectee.left > x2 || selectee.right < x1 || selectee.top > y2 || selectee.bottom < y1) );
                } else if (options.tolerance === "fit") {
                    hit = (selectee.left > x1 && selectee.right < x2 && selectee.top > y1 && selectee.bottom < y2);
                }

                if (hit) {
                    // select
                    if (selectee.selected) {
                        selectee.$element.removeclass("ui-selected");
                        selectee.selected = false;
                    }
                    if (selectee.unselecting) {
                        selectee.$element.removeclass("ui-unselecting");
                        selectee.unselecting = false;
                    }
                    if (!selectee.selecting) {
                        selectee.$element.addclass("ui-selecting");
                        selectee.selecting = true;
                        // selectable selecting callback
                        that._trigger("selecting", event, {
                            selecting: selectee.element
                        });
                    }
                } else {
                    // unselect
                    if (selectee.selecting) {
                        if ((event.metakey || event.ctrlkey) && selectee.startselected) {
                            selectee.$element.removeclass("ui-selecting");
                            selectee.selecting = false;
                            selectee.$element.addclass("ui-selected");
                            selectee.selected = true;
                        } else {
                            selectee.$element.removeclass("ui-selecting");
                            selectee.selecting = false;
                            if (selectee.startselected) {
                                selectee.$element.addclass("ui-unselecting");
                                selectee.unselecting = true;
                            }
                            // selectable unselecting callback
                            that._trigger("unselecting", event, {
                                unselecting: selectee.element
                            });
                        }
                    }
                    if (selectee.selected) {
                        if (!event.metakey && !event.ctrlkey && !selectee.startselected) {
                            selectee.$element.removeclass("ui-selected");
                            selectee.selected = false;

                            selectee.$element.addclass("ui-unselecting");
                            selectee.unselecting = true;
                            // selectable unselecting callback
                            that._trigger("unselecting", event, {
                                unselecting: selectee.element
                            });
                        }
                    }
                }
            });

            return false;
        },

        _mousestop: function(event) {
            var that = this;

            this.dragged = false;

            $(".ui-unselecting", this.element[0]).each(function() {
                var selectee = $.data(this, "selectable-item");
                selectee.$element.removeclass("ui-unselecting");
                selectee.unselecting = false;
                selectee.startselected = false;
                that._trigger("unselected", event, {
                    unselected: selectee.element
                });
            });
            $(".ui-selecting", this.element[0]).each(function() {
                var selectee = $.data(this, "selectable-item");
                selectee.$element.removeclass("ui-selecting").addclass("ui-selected");
                selectee.selecting = false;
                selectee.selected = true;
                selectee.startselected = true;
                that._trigger("selected", event, {
                    selected: selectee.element
                });
            });
            this._trigger("stop", event);

            this.helper.remove();

            return false;
        }

    });


    /*!
     * jquery ui selectmenu 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/selectmenu
     */


    var selectmenu = $.widget( "ui.selectmenu", {
        version: "1.11.2",
        defaultelement: "<select>",
        options: {
            appendto: null,
            disabled: null,
            icons: {
                button: "ui-icon-triangle-1-s"
            },
            position: {
                my: "left top",
                at: "left bottom",
                collision: "none"
            },
            width: null,

            // callbacks
            change: null,
            close: null,
            focus: null,
            open: null,
            select: null
        },

        _create: function() {
            var selectmenuid = this.element.uniqueid().attr( "id" );
            this.ids = {
                element: selectmenuid,
                button: selectmenuid + "-button",
                menu: selectmenuid + "-menu"
            };

            this._drawbutton();
            this._drawmenu();

            if ( this.options.disabled ) {
                this.disable();
            }
        },

        _drawbutton: function() {
            var that = this,
                tabindex = this.element.attr( "tabindex" );

            // associate existing label with the new button
            this.label = $( "label[for='" + this.ids.element + "']" ).attr( "for", this.ids.button );
            this._on( this.label, {
                click: function( event ) {
                    this.button.focus();
                    event.preventdefault();
                }
            });

            // hide original select element
            this.element.hide();

            // create button
            this.button = $( "<span>", {
                "class": "ui-selectmenu-button ui-widget ui-state-default ui-corner-all",
                tabindex: tabindex || this.options.disabled ? -1 : 0,
                id: this.ids.button,
                role: "combobox",
                "aria-expanded": "false",
                "aria-autocomplete": "list",
                "aria-owns": this.ids.menu,
                "aria-haspopup": "true"
            })
                .insertafter( this.element );

            $( "<span>", {
                "class": "ui-icon " + this.options.icons.button
            })
                .prependto( this.button );

            this.buttontext = $( "<span>", {
                "class": "ui-selectmenu-text"
            })
                .appendto( this.button );

            this._settext( this.buttontext, this.element.find( "option:selected" ).text() );
            this._resizebutton();

            this._on( this.button, this._buttonevents );
            this.button.one( "focusin", function() {

                // delay rendering the menu items until the button receives focus.
                // the menu may have already been rendered via a programmatic open.
                if ( !that.menuitems ) {
                    that._refreshmenu();
                }
            });
            this._hoverable( this.button );
            this._focusable( this.button );
        },

        _drawmenu: function() {
            var that = this;

            // create menu
            this.menu = $( "<ul>", {
                "aria-hidden": "true",
                "aria-labelledby": this.ids.button,
                id: this.ids.menu
            });

            // wrap menu
            this.menuwrap = $( "<div>", {
                "class": "ui-selectmenu-menu ui-front"
            })
                .append( this.menu )
                .appendto( this._appendto() );

            // initialize menu widget
            this.menuinstance = this.menu
                .menu({
                    role: "listbox",
                    select: function( event, ui ) {
                        event.preventdefault();

                        // support: ie8
                        // if the item was selected via a click, the text selection
                        // will be destroyed in ie
                        that._setselection();

                        that._select( ui.item.data( "ui-selectmenu-item" ), event );
                    },
                    focus: function( event, ui ) {
                        var item = ui.item.data( "ui-selectmenu-item" );

                        // prevent inital focus from firing and check if its a newly focused item
                        if ( that.focusindex != null && item.index !== that.focusindex ) {
                            that._trigger( "focus", event, { item: item } );
                            if ( !that.isopen ) {
                                that._select( item, event );
                            }
                        }
                        that.focusindex = item.index;

                        that.button.attr( "aria-activedescendant",
                            that.menuitems.eq( item.index ).attr( "id" ) );
                    }
                })
                .menu( "instance" );

            // adjust menu styles to dropdown
            this.menu
                .addclass( "ui-corner-bottom" )
                .removeclass( "ui-corner-all" );

            // don't close the menu on mouseleave
            this.menuinstance._off( this.menu, "mouseleave" );

            // cancel the menu's collapseall on document click
            this.menuinstance._closeondocumentclick = function() {
                return false;
            };

            // selects often contain empty items, but never contain dividers
            this.menuinstance._isdivider = function() {
                return false;
            };
        },

        refresh: function() {
            this._refreshmenu();
            this._settext( this.buttontext, this._getselecteditem().text() );
            if ( !this.options.width ) {
                this._resizebutton();
            }
        },

        _refreshmenu: function() {
            this.menu.empty();

            var item,
                options = this.element.find( "option" );

            if ( !options.length ) {
                return;
            }

            this._parseoptions( options );
            this._rendermenu( this.menu, this.items );

            this.menuinstance.refresh();
            this.menuitems = this.menu.find( "li" ).not( ".ui-selectmenu-optgroup" );

            item = this._getselecteditem();

            // update the menu to have the correct item focused
            this.menuinstance.focus( null, item );
            this._setaria( item.data( "ui-selectmenu-item" ) );

            // set disabled state
            this._setoption( "disabled", this.element.prop( "disabled" ) );
        },

        open: function( event ) {
            if ( this.options.disabled ) {
                return;
            }

            // if this is the first time the menu is being opened, render the items
            if ( !this.menuitems ) {
                this._refreshmenu();
            } else {

                // menu clears focus on close, reset focus to selected item
                this.menu.find( ".ui-state-focus" ).removeclass( "ui-state-focus" );
                this.menuinstance.focus( null, this._getselecteditem() );
            }

            this.isopen = true;
            this._toggleattr();
            this._resizemenu();
            this._position();

            this._on( this.document, this._documentclick );

            this._trigger( "open", event );
        },

        _position: function() {
            this.menuwrap.position( $.extend( { of: this.button }, this.options.position ) );
        },

        close: function( event ) {
            if ( !this.isopen ) {
                return;
            }

            this.isopen = false;
            this._toggleattr();

            this.range = null;
            this._off( this.document );

            this._trigger( "close", event );
        },

        widget: function() {
            return this.button;
        },

        menuwidget: function() {
            return this.menu;
        },

        _rendermenu: function( ul, items ) {
            var that = this,
                currentoptgroup = "";

            $.each( items, function( index, item ) {
                if ( item.optgroup !== currentoptgroup ) {
                    $( "<li>", {
                        "class": "ui-selectmenu-optgroup ui-menu-divider" +
                            ( item.element.parent( "optgroup" ).prop( "disabled" ) ?
                                " ui-state-disabled" :
                                "" ),
                        text: item.optgroup
                    })
                        .appendto( ul );

                    currentoptgroup = item.optgroup;
                }

                that._renderitemdata( ul, item );
            });
        },

        _renderitemdata: function( ul, item ) {
            return this._renderitem( ul, item ).data( "ui-selectmenu-item", item );
        },

        _renderitem: function( ul, item ) {
            var li = $( "<li>" );

            if ( item.disabled ) {
                li.addclass( "ui-state-disabled" );
            }
            this._settext( li, item.label );

            return li.appendto( ul );
        },

        _settext: function( element, value ) {
            if ( value ) {
                element.text( value );
            } else {
                element.html( "&#160;" );
            }
        },

        _move: function( direction, event ) {
            var item, next,
                filter = ".ui-menu-item";

            if ( this.isopen ) {
                item = this.menuitems.eq( this.focusindex );
            } else {
                item = this.menuitems.eq( this.element[ 0 ].selectedindex );
                filter += ":not(.ui-state-disabled)";
            }

            if ( direction === "first" || direction === "last" ) {
                next = item[ direction === "first" ? "prevall" : "nextall" ]( filter ).eq( -1 );
            } else {
                next = item[ direction + "all" ]( filter ).eq( 0 );
            }

            if ( next.length ) {
                this.menuinstance.focus( event, next );
            }
        },

        _getselecteditem: function() {
            return this.menuitems.eq( this.element[ 0 ].selectedindex );
        },

        _toggle: function( event ) {
            this[ this.isopen ? "close" : "open" ]( event );
        },

        _setselection: function() {
            var selection;

            if ( !this.range ) {
                return;
            }

            if ( window.getselection ) {
                selection = window.getselection();
                selection.removeallranges();
                selection.addrange( this.range );

                // support: ie8
            } else {
                this.range.select();
            }

            // support: ie
            // setting the text selection kills the button focus in ie, but
            // restoring the focus doesn't kill the selection.
            this.button.focus();
        },

        _documentclick: {
            mousedown: function( event ) {
                if ( !this.isopen ) {
                    return;
                }

                if ( !$( event.target ).closest( ".ui-selectmenu-menu, #" + this.ids.button ).length ) {
                    this.close( event );
                }
            }
        },

        _buttonevents: {

            // prevent text selection from being reset when interacting with the selectmenu (#10144)
            mousedown: function() {
                var selection;

                if ( window.getselection ) {
                    selection = window.getselection();
                    if ( selection.rangecount ) {
                        this.range = selection.getrangeat( 0 );
                    }

                    // support: ie8
                } else {
                    this.range = document.selection.createrange();
                }
            },

            click: function( event ) {
                this._setselection();
                this._toggle( event );
            },

            keydown: function( event ) {
                var preventdefault = true;
                switch ( event.keycode ) {
                    case $.ui.keycode.tab:
                    case $.ui.keycode.escape:
                        this.close( event );
                        preventdefault = false;
                        break;
                    case $.ui.keycode.enter:
                        if ( this.isopen ) {
                            this._selectfocuseditem( event );
                        }
                        break;
                    case $.ui.keycode.up:
                        if ( event.altkey ) {
                            this._toggle( event );
                        } else {
                            this._move( "prev", event );
                        }
                        break;
                    case $.ui.keycode.down:
                        if ( event.altkey ) {
                            this._toggle( event );
                        } else {
                            this._move( "next", event );
                        }
                        break;
                    case $.ui.keycode.space:
                        if ( this.isopen ) {
                            this._selectfocuseditem( event );
                        } else {
                            this._toggle( event );
                        }
                        break;
                    case $.ui.keycode.left:
                        this._move( "prev", event );
                        break;
                    case $.ui.keycode.right:
                        this._move( "next", event );
                        break;
                    case $.ui.keycode.home:
                    case $.ui.keycode.page_up:
                        this._move( "first", event );
                        break;
                    case $.ui.keycode.end:
                    case $.ui.keycode.page_down:
                        this._move( "last", event );
                        break;
                    default:
                        this.menu.trigger( event );
                        preventdefault = false;
                }

                if ( preventdefault ) {
                    event.preventdefault();
                }
            }
        },

        _selectfocuseditem: function( event ) {
            var item = this.menuitems.eq( this.focusindex );
            if ( !item.hasclass( "ui-state-disabled" ) ) {
                this._select( item.data( "ui-selectmenu-item" ), event );
            }
        },

        _select: function( item, event ) {
            var oldindex = this.element[ 0 ].selectedindex;

            // change native select element
            this.element[ 0 ].selectedindex = item.index;
            this._settext( this.buttontext, item.label );
            this._setaria( item );
            this._trigger( "select", event, { item: item } );

            if ( item.index !== oldindex ) {
                this._trigger( "change", event, { item: item } );
            }

            this.close( event );
        },

        _setaria: function( item ) {
            var id = this.menuitems.eq( item.index ).attr( "id" );

            this.button.attr({
                "aria-labelledby": id,
                "aria-activedescendant": id
            });
            this.menu.attr( "aria-activedescendant", id );
        },

        _setoption: function( key, value ) {
            if ( key === "icons" ) {
                this.button.find( "span.ui-icon" )
                    .removeclass( this.options.icons.button )
                    .addclass( value.button );
            }

            this._super( key, value );

            if ( key === "appendto" ) {
                this.menuwrap.appendto( this._appendto() );
            }

            if ( key === "disabled" ) {
                this.menuinstance.option( "disabled", value );
                this.button
                    .toggleclass( "ui-state-disabled", value )
                    .attr( "aria-disabled", value );

                this.element.prop( "disabled", value );
                if ( value ) {
                    this.button.attr( "tabindex", -1 );
                    this.close();
                } else {
                    this.button.attr( "tabindex", 0 );
                }
            }

            if ( key === "width" ) {
                this._resizebutton();
            }
        },

        _appendto: function() {
            var element = this.options.appendto;

            if ( element ) {
                element = element.jquery || element.nodetype ?
                    $( element ) :
                    this.document.find( element ).eq( 0 );
            }

            if ( !element || !element[ 0 ] ) {
                element = this.element.closest( ".ui-front" );
            }

            if ( !element.length ) {
                element = this.document[ 0 ].body;
            }

            return element;
        },

        _toggleattr: function() {
            this.button
                .toggleclass( "ui-corner-top", this.isopen )
                .toggleclass( "ui-corner-all", !this.isopen )
                .attr( "aria-expanded", this.isopen );
            this.menuwrap.toggleclass( "ui-selectmenu-open", this.isopen );
            this.menu.attr( "aria-hidden", !this.isopen );
        },

        _resizebutton: function() {
            var width = this.options.width;

            if ( !width ) {
                width = this.element.show().outerwidth();
                this.element.hide();
            }

            this.button.outerwidth( width );
        },

        _resizemenu: function() {
            this.menu.outerwidth( math.max(
                this.button.outerwidth(),

                // support: ie10
                // ie10 wraps long text (possibly a rounding bug)
                // so we add 1px to avoid the wrapping
                    this.menu.width( "" ).outerwidth() + 1
            ) );
        },

        _getcreateoptions: function() {
            return { disabled: this.element.prop( "disabled" ) };
        },

        _parseoptions: function( options ) {
            var data = [];
            options.each(function( index, item ) {
                var option = $( item ),
                    optgroup = option.parent( "optgroup" );
                data.push({
                    element: option,
                    index: index,
                    value: option.attr( "value" ),
                    label: option.text(),
                    optgroup: optgroup.attr( "label" ) || "",
                    disabled: optgroup.prop( "disabled" ) || option.prop( "disabled" )
                });
            });
            this.items = data;
        },

        _destroy: function() {
            this.menuwrap.remove();
            this.button.remove();
            this.element.show();
            this.element.removeuniqueid();
            this.label.attr( "for", this.ids.element );
        }
    });


    /*!
     * jquery ui slider 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/slider/
     */


    var slider = $.widget( "ui.slider", $.ui.mouse, {
        version: "1.11.2",
        widgeteventprefix: "slide",

        options: {
            animate: false,
            distance: 0,
            max: 100,
            min: 0,
            orientation: "horizontal",
            range: false,
            step: 1,
            value: 0,
            values: null,

            // callbacks
            change: null,
            slide: null,
            start: null,
            stop: null
        },

        // number of pages in a slider
        // (how many times can you page up/down to go through the whole range)
        numpages: 5,

        _create: function() {
            this._keysliding = false;
            this._mousesliding = false;
            this._animateoff = true;
            this._handleindex = null;
            this._detectorientation();
            this._mouseinit();
            this._calculatenewmax();

            this.element
                .addclass( "ui-slider" +
                    " ui-slider-" + this.orientation +
                    " ui-widget" +
                    " ui-widget-content" +
                    " ui-corner-all");

            this._refresh();
            this._setoption( "disabled", this.options.disabled );

            this._animateoff = false;
        },

        _refresh: function() {
            this._createrange();
            this._createhandles();
            this._setupevents();
            this._refreshvalue();
        },

        _createhandles: function() {
            var i, handlecount,
                options = this.options,
                existinghandles = this.element.find( ".ui-slider-handle" ).addclass( "ui-state-default ui-corner-all" ),
                handle = "<span class='ui-slider-handle ui-state-default ui-corner-all' tabindex='0'></span>",
                handles = [];

            handlecount = ( options.values && options.values.length ) || 1;

            if ( existinghandles.length > handlecount ) {
                existinghandles.slice( handlecount ).remove();
                existinghandles = existinghandles.slice( 0, handlecount );
            }

            for ( i = existinghandles.length; i < handlecount; i++ ) {
                handles.push( handle );
            }

            this.handles = existinghandles.add( $( handles.join( "" ) ).appendto( this.element ) );

            this.handle = this.handles.eq( 0 );

            this.handles.each(function( i ) {
                $( this ).data( "ui-slider-handle-index", i );
            });
        },

        _createrange: function() {
            var options = this.options,
                classes = "";

            if ( options.range ) {
                if ( options.range === true ) {
                    if ( !options.values ) {
                        options.values = [ this._valuemin(), this._valuemin() ];
                    } else if ( options.values.length && options.values.length !== 2 ) {
                        options.values = [ options.values[0], options.values[0] ];
                    } else if ( $.isarray( options.values ) ) {
                        options.values = options.values.slice(0);
                    }
                }

                if ( !this.range || !this.range.length ) {
                    this.range = $( "<div></div>" )
                        .appendto( this.element );

                    classes = "ui-slider-range" +
                        // note: this isn't the most fittingly semantic framework class for this element,
                        // but worked best visually with a variety of themes
                        " ui-widget-header ui-corner-all";
                } else {
                    this.range.removeclass( "ui-slider-range-min ui-slider-range-max" )
                        // handle range switching from true to min/max
                        .css({
                            "left": "",
                            "bottom": ""
                        });
                }

                this.range.addclass( classes +
                    ( ( options.range === "min" || options.range === "max" ) ? " ui-slider-range-" + options.range : "" ) );
            } else {
                if ( this.range ) {
                    this.range.remove();
                }
                this.range = null;
            }
        },

        _setupevents: function() {
            this._off( this.handles );
            this._on( this.handles, this._handleevents );
            this._hoverable( this.handles );
            this._focusable( this.handles );
        },

        _destroy: function() {
            this.handles.remove();
            if ( this.range ) {
                this.range.remove();
            }

            this.element
                .removeclass( "ui-slider" +
                    " ui-slider-horizontal" +
                    " ui-slider-vertical" +
                    " ui-widget" +
                    " ui-widget-content" +
                    " ui-corner-all" );

            this._mousedestroy();
        },

        _mousecapture: function( event ) {
            var position, normvalue, distance, closesthandle, index, allowed, offset, mouseoverhandle,
                that = this,
                o = this.options;

            if ( o.disabled ) {
                return false;
            }

            this.elementsize = {
                width: this.element.outerwidth(),
                height: this.element.outerheight()
            };
            this.elementoffset = this.element.offset();

            position = { x: event.pagex, y: event.pagey };
            normvalue = this._normvaluefrommouse( position );
            distance = this._valuemax() - this._valuemin() + 1;
            this.handles.each(function( i ) {
                var thisdistance = math.abs( normvalue - that.values(i) );
                if (( distance > thisdistance ) ||
                    ( distance === thisdistance &&
                        (i === that._lastchangedvalue || that.values(i) === o.min ))) {
                    distance = thisdistance;
                    closesthandle = $( this );
                    index = i;
                }
            });

            allowed = this._start( event, index );
            if ( allowed === false ) {
                return false;
            }
            this._mousesliding = true;

            this._handleindex = index;

            closesthandle
                .addclass( "ui-state-active" )
                .focus();

            offset = closesthandle.offset();
            mouseoverhandle = !$( event.target ).parents().addback().is( ".ui-slider-handle" );
            this._clickoffset = mouseoverhandle ? { left: 0, top: 0 } : {
                left: event.pagex - offset.left - ( closesthandle.width() / 2 ),
                top: event.pagey - offset.top -
                    ( closesthandle.height() / 2 ) -
                    ( parseint( closesthandle.css("bordertopwidth"), 10 ) || 0 ) -
                    ( parseint( closesthandle.css("borderbottomwidth"), 10 ) || 0) +
                    ( parseint( closesthandle.css("margintop"), 10 ) || 0)
            };

            if ( !this.handles.hasclass( "ui-state-hover" ) ) {
                this._slide( event, index, normvalue );
            }
            this._animateoff = true;
            return true;
        },

        _mousestart: function() {
            return true;
        },

        _mousedrag: function( event ) {
            var position = { x: event.pagex, y: event.pagey },
                normvalue = this._normvaluefrommouse( position );

            this._slide( event, this._handleindex, normvalue );

            return false;
        },

        _mousestop: function( event ) {
            this.handles.removeclass( "ui-state-active" );
            this._mousesliding = false;

            this._stop( event, this._handleindex );
            this._change( event, this._handleindex );

            this._handleindex = null;
            this._clickoffset = null;
            this._animateoff = false;

            return false;
        },

        _detectorientation: function() {
            this.orientation = ( this.options.orientation === "vertical" ) ? "vertical" : "horizontal";
        },

        _normvaluefrommouse: function( position ) {
            var pixeltotal,
                pixelmouse,
                percentmouse,
                valuetotal,
                valuemouse;

            if ( this.orientation === "horizontal" ) {
                pixeltotal = this.elementsize.width;
                pixelmouse = position.x - this.elementoffset.left - ( this._clickoffset ? this._clickoffset.left : 0 );
            } else {
                pixeltotal = this.elementsize.height;
                pixelmouse = position.y - this.elementoffset.top - ( this._clickoffset ? this._clickoffset.top : 0 );
            }

            percentmouse = ( pixelmouse / pixeltotal );
            if ( percentmouse > 1 ) {
                percentmouse = 1;
            }
            if ( percentmouse < 0 ) {
                percentmouse = 0;
            }
            if ( this.orientation === "vertical" ) {
                percentmouse = 1 - percentmouse;
            }

            valuetotal = this._valuemax() - this._valuemin();
            valuemouse = this._valuemin() + percentmouse * valuetotal;

            return this._trimalignvalue( valuemouse );
        },

        _start: function( event, index ) {
            var uihash = {
                handle: this.handles[ index ],
                value: this.value()
            };
            if ( this.options.values && this.options.values.length ) {
                uihash.value = this.values( index );
                uihash.values = this.values();
            }
            return this._trigger( "start", event, uihash );
        },

        _slide: function( event, index, newval ) {
            var otherval,
                newvalues,
                allowed;

            if ( this.options.values && this.options.values.length ) {
                otherval = this.values( index ? 0 : 1 );

                if ( ( this.options.values.length === 2 && this.options.range === true ) &&
                    ( ( index === 0 && newval > otherval) || ( index === 1 && newval < otherval ) )
                    ) {
                    newval = otherval;
                }

                if ( newval !== this.values( index ) ) {
                    newvalues = this.values();
                    newvalues[ index ] = newval;
                    // a slide can be canceled by returning false from the slide callback
                    allowed = this._trigger( "slide", event, {
                        handle: this.handles[ index ],
                        value: newval,
                        values: newvalues
                    } );
                    otherval = this.values( index ? 0 : 1 );
                    if ( allowed !== false ) {
                        this.values( index, newval );
                    }
                }
            } else {
                if ( newval !== this.value() ) {
                    // a slide can be canceled by returning false from the slide callback
                    allowed = this._trigger( "slide", event, {
                        handle: this.handles[ index ],
                        value: newval
                    } );
                    if ( allowed !== false ) {
                        this.value( newval );
                    }
                }
            }
        },

        _stop: function( event, index ) {
            var uihash = {
                handle: this.handles[ index ],
                value: this.value()
            };
            if ( this.options.values && this.options.values.length ) {
                uihash.value = this.values( index );
                uihash.values = this.values();
            }

            this._trigger( "stop", event, uihash );
        },

        _change: function( event, index ) {
            if ( !this._keysliding && !this._mousesliding ) {
                var uihash = {
                    handle: this.handles[ index ],
                    value: this.value()
                };
                if ( this.options.values && this.options.values.length ) {
                    uihash.value = this.values( index );
                    uihash.values = this.values();
                }

                //store the last changed value index for reference when handles overlap
                this._lastchangedvalue = index;

                this._trigger( "change", event, uihash );
            }
        },

        value: function( newvalue ) {
            if ( arguments.length ) {
                this.options.value = this._trimalignvalue( newvalue );
                this._refreshvalue();
                this._change( null, 0 );
                return;
            }

            return this._value();
        },

        values: function( index, newvalue ) {
            var vals,
                newvalues,
                i;

            if ( arguments.length > 1 ) {
                this.options.values[ index ] = this._trimalignvalue( newvalue );
                this._refreshvalue();
                this._change( null, index );
                return;
            }

            if ( arguments.length ) {
                if ( $.isarray( arguments[ 0 ] ) ) {
                    vals = this.options.values;
                    newvalues = arguments[ 0 ];
                    for ( i = 0; i < vals.length; i += 1 ) {
                        vals[ i ] = this._trimalignvalue( newvalues[ i ] );
                        this._change( null, i );
                    }
                    this._refreshvalue();
                } else {
                    if ( this.options.values && this.options.values.length ) {
                        return this._values( index );
                    } else {
                        return this.value();
                    }
                }
            } else {
                return this._values();
            }
        },

        _setoption: function( key, value ) {
            var i,
                valslength = 0;

            if ( key === "range" && this.options.range === true ) {
                if ( value === "min" ) {
                    this.options.value = this._values( 0 );
                    this.options.values = null;
                } else if ( value === "max" ) {
                    this.options.value = this._values( this.options.values.length - 1 );
                    this.options.values = null;
                }
            }

            if ( $.isarray( this.options.values ) ) {
                valslength = this.options.values.length;
            }

            if ( key === "disabled" ) {
                this.element.toggleclass( "ui-state-disabled", !!value );
            }

            this._super( key, value );

            switch ( key ) {
                case "orientation":
                    this._detectorientation();
                    this.element
                        .removeclass( "ui-slider-horizontal ui-slider-vertical" )
                        .addclass( "ui-slider-" + this.orientation );
                    this._refreshvalue();

                    // reset positioning from previous orientation
                    this.handles.css( value === "horizontal" ? "bottom" : "left", "" );
                    break;
                case "value":
                    this._animateoff = true;
                    this._refreshvalue();
                    this._change( null, 0 );
                    this._animateoff = false;
                    break;
                case "values":
                    this._animateoff = true;
                    this._refreshvalue();
                    for ( i = 0; i < valslength; i += 1 ) {
                        this._change( null, i );
                    }
                    this._animateoff = false;
                    break;
                case "step":
                case "min":
                case "max":
                    this._animateoff = true;
                    this._calculatenewmax();
                    this._refreshvalue();
                    this._animateoff = false;
                    break;
                case "range":
                    this._animateoff = true;
                    this._refresh();
                    this._animateoff = false;
                    break;
            }
        },

        //internal value getter
        // _value() returns value trimmed by min and max, aligned by step
        _value: function() {
            var val = this.options.value;
            val = this._trimalignvalue( val );

            return val;
        },

        //internal values getter
        // _values() returns array of values trimmed by min and max, aligned by step
        // _values( index ) returns single value trimmed by min and max, aligned by step
        _values: function( index ) {
            var val,
                vals,
                i;

            if ( arguments.length ) {
                val = this.options.values[ index ];
                val = this._trimalignvalue( val );

                return val;
            } else if ( this.options.values && this.options.values.length ) {
                // .slice() creates a copy of the array
                // this copy gets trimmed by min and max and then returned
                vals = this.options.values.slice();
                for ( i = 0; i < vals.length; i += 1) {
                    vals[ i ] = this._trimalignvalue( vals[ i ] );
                }

                return vals;
            } else {
                return [];
            }
        },

        // returns the step-aligned value that val is closest to, between (inclusive) min and max
        _trimalignvalue: function( val ) {
            if ( val <= this._valuemin() ) {
                return this._valuemin();
            }
            if ( val >= this._valuemax() ) {
                return this._valuemax();
            }
            var step = ( this.options.step > 0 ) ? this.options.step : 1,
                valmodstep = (val - this._valuemin()) % step,
                alignvalue = val - valmodstep;

            if ( math.abs(valmodstep) * 2 >= step ) {
                alignvalue += ( valmodstep > 0 ) ? step : ( -step );
            }

            // since javascript has problems with large floats, round
            // the final value to 5 digits after the decimal point (see #4124)
            return parsefloat( alignvalue.tofixed(5) );
        },

        _calculatenewmax: function() {
            var remainder = ( this.options.max - this._valuemin() ) % this.options.step;
            this.max = this.options.max - remainder;
        },

        _valuemin: function() {
            return this.options.min;
        },

        _valuemax: function() {
            return this.max;
        },

        _refreshvalue: function() {
            var lastvalpercent, valpercent, value, valuemin, valuemax,
                orange = this.options.range,
                o = this.options,
                that = this,
                animate = ( !this._animateoff ) ? o.animate : false,
                _set = {};

            if ( this.options.values && this.options.values.length ) {
                this.handles.each(function( i ) {
                    valpercent = ( that.values(i) - that._valuemin() ) / ( that._valuemax() - that._valuemin() ) * 100;
                    _set[ that.orientation === "horizontal" ? "left" : "bottom" ] = valpercent + "%";
                    $( this ).stop( 1, 1 )[ animate ? "animate" : "css" ]( _set, o.animate );
                    if ( that.options.range === true ) {
                        if ( that.orientation === "horizontal" ) {
                            if ( i === 0 ) {
                                that.range.stop( 1, 1 )[ animate ? "animate" : "css" ]( { left: valpercent + "%" }, o.animate );
                            }
                            if ( i === 1 ) {
                                that.range[ animate ? "animate" : "css" ]( { width: ( valpercent - lastvalpercent ) + "%" }, { queue: false, duration: o.animate } );
                            }
                        } else {
                            if ( i === 0 ) {
                                that.range.stop( 1, 1 )[ animate ? "animate" : "css" ]( { bottom: ( valpercent ) + "%" }, o.animate );
                            }
                            if ( i === 1 ) {
                                that.range[ animate ? "animate" : "css" ]( { height: ( valpercent - lastvalpercent ) + "%" }, { queue: false, duration: o.animate } );
                            }
                        }
                    }
                    lastvalpercent = valpercent;
                });
            } else {
                value = this.value();
                valuemin = this._valuemin();
                valuemax = this._valuemax();
                valpercent = ( valuemax !== valuemin ) ?
                    ( value - valuemin ) / ( valuemax - valuemin ) * 100 :
                    0;
                _set[ this.orientation === "horizontal" ? "left" : "bottom" ] = valpercent + "%";
                this.handle.stop( 1, 1 )[ animate ? "animate" : "css" ]( _set, o.animate );

                if ( orange === "min" && this.orientation === "horizontal" ) {
                    this.range.stop( 1, 1 )[ animate ? "animate" : "css" ]( { width: valpercent + "%" }, o.animate );
                }
                if ( orange === "max" && this.orientation === "horizontal" ) {
                    this.range[ animate ? "animate" : "css" ]( { width: ( 100 - valpercent ) + "%" }, { queue: false, duration: o.animate } );
                }
                if ( orange === "min" && this.orientation === "vertical" ) {
                    this.range.stop( 1, 1 )[ animate ? "animate" : "css" ]( { height: valpercent + "%" }, o.animate );
                }
                if ( orange === "max" && this.orientation === "vertical" ) {
                    this.range[ animate ? "animate" : "css" ]( { height: ( 100 - valpercent ) + "%" }, { queue: false, duration: o.animate } );
                }
            }
        },

        _handleevents: {
            keydown: function( event ) {
                var allowed, curval, newval, step,
                    index = $( event.target ).data( "ui-slider-handle-index" );

                switch ( event.keycode ) {
                    case $.ui.keycode.home:
                    case $.ui.keycode.end:
                    case $.ui.keycode.page_up:
                    case $.ui.keycode.page_down:
                    case $.ui.keycode.up:
                    case $.ui.keycode.right:
                    case $.ui.keycode.down:
                    case $.ui.keycode.left:
                        event.preventdefault();
                        if ( !this._keysliding ) {
                            this._keysliding = true;
                            $( event.target ).addclass( "ui-state-active" );
                            allowed = this._start( event, index );
                            if ( allowed === false ) {
                                return;
                            }
                        }
                        break;
                }

                step = this.options.step;
                if ( this.options.values && this.options.values.length ) {
                    curval = newval = this.values( index );
                } else {
                    curval = newval = this.value();
                }

                switch ( event.keycode ) {
                    case $.ui.keycode.home:
                        newval = this._valuemin();
                        break;
                    case $.ui.keycode.end:
                        newval = this._valuemax();
                        break;
                    case $.ui.keycode.page_up:
                        newval = this._trimalignvalue(
                                curval + ( ( this._valuemax() - this._valuemin() ) / this.numpages )
                        );
                        break;
                    case $.ui.keycode.page_down:
                        newval = this._trimalignvalue(
                                curval - ( (this._valuemax() - this._valuemin()) / this.numpages ) );
                        break;
                    case $.ui.keycode.up:
                    case $.ui.keycode.right:
                        if ( curval === this._valuemax() ) {
                            return;
                        }
                        newval = this._trimalignvalue( curval + step );
                        break;
                    case $.ui.keycode.down:
                    case $.ui.keycode.left:
                        if ( curval === this._valuemin() ) {
                            return;
                        }
                        newval = this._trimalignvalue( curval - step );
                        break;
                }

                this._slide( event, index, newval );
            },
            keyup: function( event ) {
                var index = $( event.target ).data( "ui-slider-handle-index" );

                if ( this._keysliding ) {
                    this._keysliding = false;
                    this._stop( event, index );
                    this._change( event, index );
                    $( event.target ).removeclass( "ui-state-active" );
                }
            }
        }
    });


    /*!
     * jquery ui sortable 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/sortable/
     */


    var sortable = $.widget("ui.sortable", $.ui.mouse, {
        version: "1.11.2",
        widgeteventprefix: "sort",
        ready: false,
        options: {
            appendto: "parent",
            axis: false,
            connectwith: false,
            containment: false,
            cursor: "auto",
            cursorat: false,
            droponempty: true,
            forceplaceholdersize: false,
            forcehelpersize: false,
            grid: false,
            handle: false,
            helper: "original",
            items: "> *",
            opacity: false,
            placeholder: false,
            revert: false,
            scroll: true,
            scrollsensitivity: 20,
            scrollspeed: 20,
            scope: "default",
            tolerance: "intersect",
            zindex: 1000,

            // callbacks
            activate: null,
            beforestop: null,
            change: null,
            deactivate: null,
            out: null,
            over: null,
            receive: null,
            remove: null,
            sort: null,
            start: null,
            stop: null,
            update: null
        },

        _isoveraxis: function( x, reference, size ) {
            return ( x >= reference ) && ( x < ( reference + size ) );
        },

        _isfloating: function( item ) {
            return (/left|right/).test(item.css("float")) || (/inline|table-cell/).test(item.css("display"));
        },

        _create: function() {

            var o = this.options;
            this.containercache = {};
            this.element.addclass("ui-sortable");

            //get the items
            this.refresh();

            //let's determine if the items are being displayed horizontally
            this.floating = this.items.length ? o.axis === "x" || this._isfloating(this.items[0].item) : false;

            //let's determine the parent's offset
            this.offset = this.element.offset();

            //initialize mouse events for interaction
            this._mouseinit();

            this._sethandleclassname();

            //we're ready to go
            this.ready = true;

        },

        _setoption: function( key, value ) {
            this._super( key, value );

            if ( key === "handle" ) {
                this._sethandleclassname();
            }
        },

        _sethandleclassname: function() {
            this.element.find( ".ui-sortable-handle" ).removeclass( "ui-sortable-handle" );
            $.each( this.items, function() {
                ( this.instance.options.handle ?
                    this.item.find( this.instance.options.handle ) : this.item )
                    .addclass( "ui-sortable-handle" );
            });
        },

        _destroy: function() {
            this.element
                .removeclass( "ui-sortable ui-sortable-disabled" )
                .find( ".ui-sortable-handle" )
                .removeclass( "ui-sortable-handle" );
            this._mousedestroy();

            for ( var i = this.items.length - 1; i >= 0; i-- ) {
                this.items[i].item.removedata(this.widgetname + "-item");
            }

            return this;
        },

        _mousecapture: function(event, overridehandle) {
            var currentitem = null,
                validhandle = false,
                that = this;

            if (this.reverting) {
                return false;
            }

            if(this.options.disabled || this.options.type === "static") {
                return false;
            }

            //we have to refresh the items data once first
            this._refreshitems(event);

            //find out if the clicked node (or one of its parents) is a actual item in this.items
            $(event.target).parents().each(function() {
                if($.data(this, that.widgetname + "-item") === that) {
                    currentitem = $(this);
                    return false;
                }
            });
            if($.data(event.target, that.widgetname + "-item") === that) {
                currentitem = $(event.target);
            }

            if(!currentitem) {
                return false;
            }
            if(this.options.handle && !overridehandle) {
                $(this.options.handle, currentitem).find("*").addback().each(function() {
                    if(this === event.target) {
                        validhandle = true;
                    }
                });
                if(!validhandle) {
                    return false;
                }
            }

            this.currentitem = currentitem;
            this._removecurrentsfromitems();
            return true;

        },

        _mousestart: function(event, overridehandle, noactivation) {

            var i, body,
                o = this.options;

            this.currentcontainer = this;

            //we only need to call refreshpositions, because the refreshitems call has been moved to mousecapture
            this.refreshpositions();

            //create and append the visible helper
            this.helper = this._createhelper(event);

            //cache the helper size
            this._cachehelperproportions();

            /*
             * - position generation -
             * this block generates everything position related - it's the core of draggables.
             */

            //cache the margins of the original element
            this._cachemargins();

            //get the next scrolling parent
            this.scrollparent = this.helper.scrollparent();

            //the element's absolute position on the page minus margins
            this.offset = this.currentitem.offset();
            this.offset = {
                top: this.offset.top - this.margins.top,
                left: this.offset.left - this.margins.left
            };

            $.extend(this.offset, {
                click: { //where the click happened, relative to the element
                    left: event.pagex - this.offset.left,
                    top: event.pagey - this.offset.top
                },
                parent: this._getparentoffset(),
                relative: this._getrelativeoffset() //this is a relative to absolute position minus the actual position calculation - only used for relative positioned helper
            });

            // only after we got the offset, we can change the helper's position to absolute
            // todo: still need to figure out a way to make relative sorting possible
            this.helper.css("position", "absolute");
            this.cssposition = this.helper.css("position");

            //generate the original position
            this.originalposition = this._generateposition(event);
            this.originalpagex = event.pagex;
            this.originalpagey = event.pagey;

            //adjust the mouse offset relative to the helper if "cursorat" is supplied
            (o.cursorat && this._adjustoffsetfromhelper(o.cursorat));

            //cache the former dom position
            this.domposition = { prev: this.currentitem.prev()[0], parent: this.currentitem.parent()[0] };

            //if the helper is not the original, hide the original so it's not playing any role during the drag, won't cause anything bad this way
            if(this.helper[0] !== this.currentitem[0]) {
                this.currentitem.hide();
            }

            //create the placeholder
            this._createplaceholder();

            //set a containment if given in the options
            if(o.containment) {
                this._setcontainment();
            }

            if( o.cursor && o.cursor !== "auto" ) { // cursor option
                body = this.document.find( "body" );

                // support: ie
                this.storedcursor = body.css( "cursor" );
                body.css( "cursor", o.cursor );

                this.storedstylesheet = $( "<style>*{ cursor: "+o.cursor+" !important; }</style>" ).appendto( body );
            }

            if(o.opacity) { // opacity option
                if (this.helper.css("opacity")) {
                    this._storedopacity = this.helper.css("opacity");
                }
                this.helper.css("opacity", o.opacity);
            }

            if(o.zindex) { // zindex option
                if (this.helper.css("zindex")) {
                    this._storedzindex = this.helper.css("zindex");
                }
                this.helper.css("zindex", o.zindex);
            }

            //prepare scrolling
            if(this.scrollparent[0] !== document && this.scrollparent[0].tagname !== "html") {
                this.overflowoffset = this.scrollparent.offset();
            }

            //call callbacks
            this._trigger("start", event, this._uihash());

            //recache the helper size
            if(!this._preservehelperproportions) {
                this._cachehelperproportions();
            }


            //post "activate" events to possible containers
            if( !noactivation ) {
                for ( i = this.containers.length - 1; i >= 0; i-- ) {
                    this.containers[ i ]._trigger( "activate", event, this._uihash( this ) );
                }
            }

            //prepare possible droppables
            if($.ui.ddmanager) {
                $.ui.ddmanager.current = this;
            }

            if ($.ui.ddmanager && !o.dropbehaviour) {
                $.ui.ddmanager.prepareoffsets(this, event);
            }

            this.dragging = true;

            this.helper.addclass("ui-sortable-helper");
            this._mousedrag(event); //execute the drag once - this causes the helper not to be visible before getting its correct position
            return true;

        },

        _mousedrag: function(event) {
            var i, item, itemelement, intersection,
                o = this.options,
                scrolled = false;

            //compute the helpers position
            this.position = this._generateposition(event);
            this.positionabs = this._convertpositionto("absolute");

            if (!this.lastpositionabs) {
                this.lastpositionabs = this.positionabs;
            }

            //do scrolling
            if(this.options.scroll) {
                if(this.scrollparent[0] !== document && this.scrollparent[0].tagname !== "html") {

                    if((this.overflowoffset.top + this.scrollparent[0].offsetheight) - event.pagey < o.scrollsensitivity) {
                        this.scrollparent[0].scrolltop = scrolled = this.scrollparent[0].scrolltop + o.scrollspeed;
                    } else if(event.pagey - this.overflowoffset.top < o.scrollsensitivity) {
                        this.scrollparent[0].scrolltop = scrolled = this.scrollparent[0].scrolltop - o.scrollspeed;
                    }

                    if((this.overflowoffset.left + this.scrollparent[0].offsetwidth) - event.pagex < o.scrollsensitivity) {
                        this.scrollparent[0].scrollleft = scrolled = this.scrollparent[0].scrollleft + o.scrollspeed;
                    } else if(event.pagex - this.overflowoffset.left < o.scrollsensitivity) {
                        this.scrollparent[0].scrollleft = scrolled = this.scrollparent[0].scrollleft - o.scrollspeed;
                    }

                } else {

                    if(event.pagey - $(document).scrolltop() < o.scrollsensitivity) {
                        scrolled = $(document).scrolltop($(document).scrolltop() - o.scrollspeed);
                    } else if($(window).height() - (event.pagey - $(document).scrolltop()) < o.scrollsensitivity) {
                        scrolled = $(document).scrolltop($(document).scrolltop() + o.scrollspeed);
                    }

                    if(event.pagex - $(document).scrollleft() < o.scrollsensitivity) {
                        scrolled = $(document).scrollleft($(document).scrollleft() - o.scrollspeed);
                    } else if($(window).width() - (event.pagex - $(document).scrollleft()) < o.scrollsensitivity) {
                        scrolled = $(document).scrollleft($(document).scrollleft() + o.scrollspeed);
                    }

                }

                if(scrolled !== false && $.ui.ddmanager && !o.dropbehaviour) {
                    $.ui.ddmanager.prepareoffsets(this, event);
                }
            }

            //regenerate the absolute position used for position checks
            this.positionabs = this._convertpositionto("absolute");

            //set the helper position
            if(!this.options.axis || this.options.axis !== "y") {
                this.helper[0].style.left = this.position.left+"px";
            }
            if(!this.options.axis || this.options.axis !== "x") {
                this.helper[0].style.top = this.position.top+"px";
            }

            //rearrange
            for (i = this.items.length - 1; i >= 0; i--) {

                //cache variables and intersection, continue if no intersection
                item = this.items[i];
                itemelement = item.item[0];
                intersection = this._intersectswithpointer(item);
                if (!intersection) {
                    continue;
                }

                // only put the placeholder inside the current container, skip all
                // items from other containers. this works because when moving
                // an item from one container to another the
                // currentcontainer is switched before the placeholder is moved.
                //
                // without this, moving items in "sub-sortables" can cause
                // the placeholder to jitter between the outer and inner container.
                if (item.instance !== this.currentcontainer) {
                    continue;
                }

                // cannot intersect with itself
                // no useless actions that have been done before
                // no action if the item moved is the parent of the item checked
                if (itemelement !== this.currentitem[0] &&
                    this.placeholder[intersection === 1 ? "next" : "prev"]()[0] !== itemelement &&
                    !$.contains(this.placeholder[0], itemelement) &&
                    (this.options.type === "semi-dynamic" ? !$.contains(this.element[0], itemelement) : true)
                    ) {

                    this.direction = intersection === 1 ? "down" : "up";

                    if (this.options.tolerance === "pointer" || this._intersectswithsides(item)) {
                        this._rearrange(event, item);
                    } else {
                        break;
                    }

                    this._trigger("change", event, this._uihash());
                    break;
                }
            }

            //post events to containers
            this._contactcontainers(event);

            //interconnect with droppables
            if($.ui.ddmanager) {
                $.ui.ddmanager.drag(this, event);
            }

            //call callbacks
            this._trigger("sort", event, this._uihash());

            this.lastpositionabs = this.positionabs;
            return false;

        },

        _mousestop: function(event, nopropagation) {

            if(!event) {
                return;
            }

            //if we are using droppables, inform the manager about the drop
            if ($.ui.ddmanager && !this.options.dropbehaviour) {
                $.ui.ddmanager.drop(this, event);
            }

            if(this.options.revert) {
                var that = this,
                    cur = this.placeholder.offset(),
                    axis = this.options.axis,
                    animation = {};

                if ( !axis || axis === "x" ) {
                    animation.left = cur.left - this.offset.parent.left - this.margins.left + (this.offsetparent[0] === document.body ? 0 : this.offsetparent[0].scrollleft);
                }
                if ( !axis || axis === "y" ) {
                    animation.top = cur.top - this.offset.parent.top - this.margins.top + (this.offsetparent[0] === document.body ? 0 : this.offsetparent[0].scrolltop);
                }
                this.reverting = true;
                $(this.helper).animate( animation, parseint(this.options.revert, 10) || 500, function() {
                    that._clear(event);
                });
            } else {
                this._clear(event, nopropagation);
            }

            return false;

        },

        cancel: function() {

            if(this.dragging) {

                this._mouseup({ target: null });

                if(this.options.helper === "original") {
                    this.currentitem.css(this._storedcss).removeclass("ui-sortable-helper");
                } else {
                    this.currentitem.show();
                }

                //post deactivating events to containers
                for (var i = this.containers.length - 1; i >= 0; i--){
                    this.containers[i]._trigger("deactivate", null, this._uihash(this));
                    if(this.containers[i].containercache.over) {
                        this.containers[i]._trigger("out", null, this._uihash(this));
                        this.containers[i].containercache.over = 0;
                    }
                }

            }

            if (this.placeholder) {
                //$(this.placeholder[0]).remove(); would have been the jquery way - unfortunately, it unbinds all events from the original node!
                if(this.placeholder[0].parentnode) {
                    this.placeholder[0].parentnode.removechild(this.placeholder[0]);
                }
                if(this.options.helper !== "original" && this.helper && this.helper[0].parentnode) {
                    this.helper.remove();
                }

                $.extend(this, {
                    helper: null,
                    dragging: false,
                    reverting: false,
                    _nofinalsort: null
                });

                if(this.domposition.prev) {
                    $(this.domposition.prev).after(this.currentitem);
                } else {
                    $(this.domposition.parent).prepend(this.currentitem);
                }
            }

            return this;

        },

        serialize: function(o) {

            var items = this._getitemsasjquery(o && o.connected),
                str = [];
            o = o || {};

            $(items).each(function() {
                var res = ($(o.item || this).attr(o.attribute || "id") || "").match(o.expression || (/(.+)[\-=_](.+)/));
                if (res) {
                    str.push((o.key || res[1]+"[]")+"="+(o.key && o.expression ? res[1] : res[2]));
                }
            });

            if(!str.length && o.key) {
                str.push(o.key + "=");
            }

            return str.join("&");

        },

        toarray: function(o) {

            var items = this._getitemsasjquery(o && o.connected),
                ret = [];

            o = o || {};

            items.each(function() { ret.push($(o.item || this).attr(o.attribute || "id") || ""); });
            return ret;

        },

        /* be careful with the following core functions */
        _intersectswith: function(item) {

            var x1 = this.positionabs.left,
                x2 = x1 + this.helperproportions.width,
                y1 = this.positionabs.top,
                y2 = y1 + this.helperproportions.height,
                l = item.left,
                r = l + item.width,
                t = item.top,
                b = t + item.height,
                dyclick = this.offset.click.top,
                dxclick = this.offset.click.left,
                isoverelementheight = ( this.options.axis === "x" ) || ( ( y1 + dyclick ) > t && ( y1 + dyclick ) < b ),
                isoverelementwidth = ( this.options.axis === "y" ) || ( ( x1 + dxclick ) > l && ( x1 + dxclick ) < r ),
                isoverelement = isoverelementheight && isoverelementwidth;

            if ( this.options.tolerance === "pointer" ||
                this.options.forcepointerforcontainers ||
                (this.options.tolerance !== "pointer" && this.helperproportions[this.floating ? "width" : "height"] > item[this.floating ? "width" : "height"])
                ) {
                return isoverelement;
            } else {

                return (l < x1 + (this.helperproportions.width / 2) && // right half
                    x2 - (this.helperproportions.width / 2) < r && // left half
                    t < y1 + (this.helperproportions.height / 2) && // bottom half
                    y2 - (this.helperproportions.height / 2) < b ); // top half

            }
        },

        _intersectswithpointer: function(item) {

            var isoverelementheight = (this.options.axis === "x") || this._isoveraxis(this.positionabs.top + this.offset.click.top, item.top, item.height),
                isoverelementwidth = (this.options.axis === "y") || this._isoveraxis(this.positionabs.left + this.offset.click.left, item.left, item.width),
                isoverelement = isoverelementheight && isoverelementwidth,
                verticaldirection = this._getdragverticaldirection(),
                horizontaldirection = this._getdraghorizontaldirection();

            if (!isoverelement) {
                return false;
            }

            return this.floating ?
                ( ((horizontaldirection && horizontaldirection === "right") || verticaldirection === "down") ? 2 : 1 )
                : ( verticaldirection && (verticaldirection === "down" ? 2 : 1) );

        },

        _intersectswithsides: function(item) {

            var isoverbottomhalf = this._isoveraxis(this.positionabs.top + this.offset.click.top, item.top + (item.height/2), item.height),
                isoverrighthalf = this._isoveraxis(this.positionabs.left + this.offset.click.left, item.left + (item.width/2), item.width),
                verticaldirection = this._getdragverticaldirection(),
                horizontaldirection = this._getdraghorizontaldirection();

            if (this.floating && horizontaldirection) {
                return ((horizontaldirection === "right" && isoverrighthalf) || (horizontaldirection === "left" && !isoverrighthalf));
            } else {
                return verticaldirection && ((verticaldirection === "down" && isoverbottomhalf) || (verticaldirection === "up" && !isoverbottomhalf));
            }

        },

        _getdragverticaldirection: function() {
            var delta = this.positionabs.top - this.lastpositionabs.top;
            return delta !== 0 && (delta > 0 ? "down" : "up");
        },

        _getdraghorizontaldirection: function() {
            var delta = this.positionabs.left - this.lastpositionabs.left;
            return delta !== 0 && (delta > 0 ? "right" : "left");
        },

        refresh: function(event) {
            this._refreshitems(event);
            this._sethandleclassname();
            this.refreshpositions();
            return this;
        },

        _connectwith: function() {
            var options = this.options;
            return options.connectwith.constructor === string ? [options.connectwith] : options.connectwith;
        },

        _getitemsasjquery: function(connected) {

            var i, j, cur, inst,
                items = [],
                queries = [],
                connectwith = this._connectwith();

            if(connectwith && connected) {
                for (i = connectwith.length - 1; i >= 0; i--){
                    cur = $(connectwith[i]);
                    for ( j = cur.length - 1; j >= 0; j--){
                        inst = $.data(cur[j], this.widgetfullname);
                        if(inst && inst !== this && !inst.options.disabled) {
                            queries.push([$.isfunction(inst.options.items) ? inst.options.items.call(inst.element) : $(inst.options.items, inst.element).not(".ui-sortable-helper").not(".ui-sortable-placeholder"), inst]);
                        }
                    }
                }
            }

            queries.push([$.isfunction(this.options.items) ? this.options.items.call(this.element, null, { options: this.options, item: this.currentitem }) : $(this.options.items, this.element).not(".ui-sortable-helper").not(".ui-sortable-placeholder"), this]);

            function additems() {
                items.push( this );
            }
            for (i = queries.length - 1; i >= 0; i--){
                queries[i][0].each( additems );
            }

            return $(items);

        },

        _removecurrentsfromitems: function() {

            var list = this.currentitem.find(":data(" + this.widgetname + "-item)");

            this.items = $.grep(this.items, function (item) {
                for (var j=0; j < list.length; j++) {
                    if(list[j] === item.item[0]) {
                        return false;
                    }
                }
                return true;
            });

        },

        _refreshitems: function(event) {

            this.items = [];
            this.containers = [this];

            var i, j, cur, inst, targetdata, _queries, item, querieslength,
                items = this.items,
                queries = [[$.isfunction(this.options.items) ? this.options.items.call(this.element[0], event, { item: this.currentitem }) : $(this.options.items, this.element), this]],
                connectwith = this._connectwith();

            if(connectwith && this.ready) { //shouldn't be run the first time through due to massive slow-down
                for (i = connectwith.length - 1; i >= 0; i--){
                    cur = $(connectwith[i]);
                    for (j = cur.length - 1; j >= 0; j--){
                        inst = $.data(cur[j], this.widgetfullname);
                        if(inst && inst !== this && !inst.options.disabled) {
                            queries.push([$.isfunction(inst.options.items) ? inst.options.items.call(inst.element[0], event, { item: this.currentitem }) : $(inst.options.items, inst.element), inst]);
                            this.containers.push(inst);
                        }
                    }
                }
            }

            for (i = queries.length - 1; i >= 0; i--) {
                targetdata = queries[i][1];
                _queries = queries[i][0];

                for (j=0, querieslength = _queries.length; j < querieslength; j++) {
                    item = $(_queries[j]);

                    item.data(this.widgetname + "-item", targetdata); // data for target checking (mouse manager)

                    items.push({
                        item: item,
                        instance: targetdata,
                        width: 0, height: 0,
                        left: 0, top: 0
                    });
                }
            }

        },

        refreshpositions: function(fast) {

            //this has to be redone because due to the item being moved out/into the offsetparent, the offsetparent's position will change
            if(this.offsetparent && this.helper) {
                this.offset.parent = this._getparentoffset();
            }

            var i, item, t, p;

            for (i = this.items.length - 1; i >= 0; i--){
                item = this.items[i];

                //we ignore calculating positions of all connected containers when we're not over them
                if(item.instance !== this.currentcontainer && this.currentcontainer && item.item[0] !== this.currentitem[0]) {
                    continue;
                }

                t = this.options.toleranceelement ? $(this.options.toleranceelement, item.item) : item.item;

                if (!fast) {
                    item.width = t.outerwidth();
                    item.height = t.outerheight();
                }

                p = t.offset();
                item.left = p.left;
                item.top = p.top;
            }

            if(this.options.custom && this.options.custom.refreshcontainers) {
                this.options.custom.refreshcontainers.call(this);
            } else {
                for (i = this.containers.length - 1; i >= 0; i--){
                    p = this.containers[i].element.offset();
                    this.containers[i].containercache.left = p.left;
                    this.containers[i].containercache.top = p.top;
                    this.containers[i].containercache.width = this.containers[i].element.outerwidth();
                    this.containers[i].containercache.height = this.containers[i].element.outerheight();
                }
            }

            return this;
        },

        _createplaceholder: function(that) {
            that = that || this;
            var classname,
                o = that.options;

            if(!o.placeholder || o.placeholder.constructor === string) {
                classname = o.placeholder;
                o.placeholder = {
                    element: function() {

                        var nodename = that.currentitem[0].nodename.tolowercase(),
                            element = $( "<" + nodename + ">", that.document[0] )
                                .addclass(classname || that.currentitem[0].classname+" ui-sortable-placeholder")
                                .removeclass("ui-sortable-helper");

                        if ( nodename === "tr" ) {
                            that.currentitem.children().each(function() {
                                $( "<td>&#160;</td>", that.document[0] )
                                    .attr( "colspan", $( this ).attr( "colspan" ) || 1 )
                                    .appendto( element );
                            });
                        } else if ( nodename === "img" ) {
                            element.attr( "src", that.currentitem.attr( "src" ) );
                        }

                        if ( !classname ) {
                            element.css( "visibility", "hidden" );
                        }

                        return element;
                    },
                    update: function(container, p) {

                        // 1. if a classname is set as 'placeholder option, we don't force sizes - the class is responsible for that
                        // 2. the option 'forceplaceholdersize can be enabled to force it even if a class name is specified
                        if(classname && !o.forceplaceholdersize) {
                            return;
                        }

                        //if the element doesn't have a actual height by itself (without styles coming from a stylesheet), it receives the inline height from the dragged item
                        if(!p.height()) { p.height(that.currentitem.innerheight() - parseint(that.currentitem.css("paddingtop")||0, 10) - parseint(that.currentitem.css("paddingbottom")||0, 10)); }
                        if(!p.width()) { p.width(that.currentitem.innerwidth() - parseint(that.currentitem.css("paddingleft")||0, 10) - parseint(that.currentitem.css("paddingright")||0, 10)); }
                    }
                };
            }

            //create the placeholder
            that.placeholder = $(o.placeholder.element.call(that.element, that.currentitem));

            //append it after the actual current item
            that.currentitem.after(that.placeholder);

            //update the size of the placeholder (todo: logic to fuzzy, see line 316/317)
            o.placeholder.update(that, that.placeholder);

        },

        _contactcontainers: function(event) {
            var i, j, dist, itemwithleastdistance, posproperty, sizeproperty, cur, nearbottom, floating, axis,
                innermostcontainer = null,
                innermostindex = null;

            // get innermost container that intersects with item
            for (i = this.containers.length - 1; i >= 0; i--) {

                // never consider a container that's located within the item itself
                if($.contains(this.currentitem[0], this.containers[i].element[0])) {
                    continue;
                }

                if(this._intersectswith(this.containers[i].containercache)) {

                    // if we've already found a container and it's more "inner" than this, then continue
                    if(innermostcontainer && $.contains(this.containers[i].element[0], innermostcontainer.element[0])) {
                        continue;
                    }

                    innermostcontainer = this.containers[i];
                    innermostindex = i;

                } else {
                    // container doesn't intersect. trigger "out" event if necessary
                    if(this.containers[i].containercache.over) {
                        this.containers[i]._trigger("out", event, this._uihash(this));
                        this.containers[i].containercache.over = 0;
                    }
                }

            }

            // if no intersecting containers found, return
            if(!innermostcontainer) {
                return;
            }

            // move the item into the container if it's not there already
            if(this.containers.length === 1) {
                if (!this.containers[innermostindex].containercache.over) {
                    this.containers[innermostindex]._trigger("over", event, this._uihash(this));
                    this.containers[innermostindex].containercache.over = 1;
                }
            } else {

                //when entering a new container, we will find the item with the least distance and append our item near it
                dist = 10000;
                itemwithleastdistance = null;
                floating = innermostcontainer.floating || this._isfloating(this.currentitem);
                posproperty = floating ? "left" : "top";
                sizeproperty = floating ? "width" : "height";
                axis = floating ? "clientx" : "clienty";

                for (j = this.items.length - 1; j >= 0; j--) {
                    if(!$.contains(this.containers[innermostindex].element[0], this.items[j].item[0])) {
                        continue;
                    }
                    if(this.items[j].item[0] === this.currentitem[0]) {
                        continue;
                    }

                    cur = this.items[j].item.offset()[posproperty];
                    nearbottom = false;
                    if ( event[ axis ] - cur > this.items[ j ][ sizeproperty ] / 2 ) {
                        nearbottom = true;
                    }

                    if ( math.abs( event[ axis ] - cur ) < dist ) {
                        dist = math.abs( event[ axis ] - cur );
                        itemwithleastdistance = this.items[ j ];
                        this.direction = nearbottom ? "up": "down";
                    }
                }

                //check if droponempty is enabled
                if(!itemwithleastdistance && !this.options.droponempty) {
                    return;
                }

                if(this.currentcontainer === this.containers[innermostindex]) {
                    if ( !this.currentcontainer.containercache.over ) {
                        this.containers[ innermostindex ]._trigger( "over", event, this._uihash() );
                        this.currentcontainer.containercache.over = 1;
                    }
                    return;
                }

                itemwithleastdistance ? this._rearrange(event, itemwithleastdistance, null, true) : this._rearrange(event, null, this.containers[innermostindex].element, true);
                this._trigger("change", event, this._uihash());
                this.containers[innermostindex]._trigger("change", event, this._uihash(this));
                this.currentcontainer = this.containers[innermostindex];

                //update the placeholder
                this.options.placeholder.update(this.currentcontainer, this.placeholder);

                this.containers[innermostindex]._trigger("over", event, this._uihash(this));
                this.containers[innermostindex].containercache.over = 1;
            }


        },

        _createhelper: function(event) {

            var o = this.options,
                helper = $.isfunction(o.helper) ? $(o.helper.apply(this.element[0], [event, this.currentitem])) : (o.helper === "clone" ? this.currentitem.clone() : this.currentitem);

            //add the helper to the dom if that didn't happen already
            if(!helper.parents("body").length) {
                $(o.appendto !== "parent" ? o.appendto : this.currentitem[0].parentnode)[0].appendchild(helper[0]);
            }

            if(helper[0] === this.currentitem[0]) {
                this._storedcss = { width: this.currentitem[0].style.width, height: this.currentitem[0].style.height, position: this.currentitem.css("position"), top: this.currentitem.css("top"), left: this.currentitem.css("left") };
            }

            if(!helper[0].style.width || o.forcehelpersize) {
                helper.width(this.currentitem.width());
            }
            if(!helper[0].style.height || o.forcehelpersize) {
                helper.height(this.currentitem.height());
            }

            return helper;

        },

        _adjustoffsetfromhelper: function(obj) {
            if (typeof obj === "string") {
                obj = obj.split(" ");
            }
            if ($.isarray(obj)) {
                obj = {left: +obj[0], top: +obj[1] || 0};
            }
            if ("left" in obj) {
                this.offset.click.left = obj.left + this.margins.left;
            }
            if ("right" in obj) {
                this.offset.click.left = this.helperproportions.width - obj.right + this.margins.left;
            }
            if ("top" in obj) {
                this.offset.click.top = obj.top + this.margins.top;
            }
            if ("bottom" in obj) {
                this.offset.click.top = this.helperproportions.height - obj.bottom + this.margins.top;
            }
        },

        _getparentoffset: function() {


            //get the offsetparent and cache its position
            this.offsetparent = this.helper.offsetparent();
            var po = this.offsetparent.offset();

            // this is a special case where we need to modify a offset calculated on start, since the following happened:
            // 1. the position of the helper is absolute, so it's position is calculated based on the next positioned parent
            // 2. the actual offset parent is a child of the scroll parent, and the scroll parent isn't the document, which means that
            //    the scroll is included in the initial calculation of the offset of the parent, and never recalculated upon drag
            if(this.cssposition === "absolute" && this.scrollparent[0] !== document && $.contains(this.scrollparent[0], this.offsetparent[0])) {
                po.left += this.scrollparent.scrollleft();
                po.top += this.scrollparent.scrolltop();
            }

            // this needs to be actually done for all browsers, since pagex/pagey includes this information
            // with an ugly ie fix
            if( this.offsetparent[0] === document.body || (this.offsetparent[0].tagname && this.offsetparent[0].tagname.tolowercase() === "html" && $.ui.ie)) {
                po = { top: 0, left: 0 };
            }

            return {
                top: po.top + (parseint(this.offsetparent.css("bordertopwidth"),10) || 0),
                left: po.left + (parseint(this.offsetparent.css("borderleftwidth"),10) || 0)
            };

        },

        _getrelativeoffset: function() {

            if(this.cssposition === "relative") {
                var p = this.currentitem.position();
                return {
                    top: p.top - (parseint(this.helper.css("top"),10) || 0) + this.scrollparent.scrolltop(),
                    left: p.left - (parseint(this.helper.css("left"),10) || 0) + this.scrollparent.scrollleft()
                };
            } else {
                return { top: 0, left: 0 };
            }

        },

        _cachemargins: function() {
            this.margins = {
                left: (parseint(this.currentitem.css("marginleft"),10) || 0),
                top: (parseint(this.currentitem.css("margintop"),10) || 0)
            };
        },

        _cachehelperproportions: function() {
            this.helperproportions = {
                width: this.helper.outerwidth(),
                height: this.helper.outerheight()
            };
        },

        _setcontainment: function() {

            var ce, co, over,
                o = this.options;
            if(o.containment === "parent") {
                o.containment = this.helper[0].parentnode;
            }
            if(o.containment === "document" || o.containment === "window") {
                this.containment = [
                        0 - this.offset.relative.left - this.offset.parent.left,
                        0 - this.offset.relative.top - this.offset.parent.top,
                        $(o.containment === "document" ? document : window).width() - this.helperproportions.width - this.margins.left,
                        ($(o.containment === "document" ? document : window).height() || document.body.parentnode.scrollheight) - this.helperproportions.height - this.margins.top
                ];
            }

            if(!(/^(document|window|parent)$/).test(o.containment)) {
                ce = $(o.containment)[0];
                co = $(o.containment).offset();
                over = ($(ce).css("overflow") !== "hidden");

                this.containment = [
                        co.left + (parseint($(ce).css("borderleftwidth"),10) || 0) + (parseint($(ce).css("paddingleft"),10) || 0) - this.margins.left,
                        co.top + (parseint($(ce).css("bordertopwidth"),10) || 0) + (parseint($(ce).css("paddingtop"),10) || 0) - this.margins.top,
                        co.left+(over ? math.max(ce.scrollwidth,ce.offsetwidth) : ce.offsetwidth) - (parseint($(ce).css("borderleftwidth"),10) || 0) - (parseint($(ce).css("paddingright"),10) || 0) - this.helperproportions.width - this.margins.left,
                        co.top+(over ? math.max(ce.scrollheight,ce.offsetheight) : ce.offsetheight) - (parseint($(ce).css("bordertopwidth"),10) || 0) - (parseint($(ce).css("paddingbottom"),10) || 0) - this.helperproportions.height - this.margins.top
                ];
            }

        },

        _convertpositionto: function(d, pos) {

            if(!pos) {
                pos = this.position;
            }
            var mod = d === "absolute" ? 1 : -1,
                scroll = this.cssposition === "absolute" && !(this.scrollparent[0] !== document && $.contains(this.scrollparent[0], this.offsetparent[0])) ? this.offsetparent : this.scrollparent,
                scrollisrootnode = (/(html|body)/i).test(scroll[0].tagname);

            return {
                top: (
                    pos.top	+																// the absolute mouse position
                    this.offset.relative.top * mod +										// only for relative positioned nodes: relative offset from element to offset parent
                    this.offset.parent.top * mod -											// the offsetparent's offset without borders (offset + border)
                    ( ( this.cssposition === "fixed" ? -this.scrollparent.scrolltop() : ( scrollisrootnode ? 0 : scroll.scrolltop() ) ) * mod)
                    ),
                left: (
                    pos.left +																// the absolute mouse position
                    this.offset.relative.left * mod +										// only for relative positioned nodes: relative offset from element to offset parent
                    this.offset.parent.left * mod	-										// the offsetparent's offset without borders (offset + border)
                    ( ( this.cssposition === "fixed" ? -this.scrollparent.scrollleft() : scrollisrootnode ? 0 : scroll.scrollleft() ) * mod)
                    )
            };

        },

        _generateposition: function(event) {

            var top, left,
                o = this.options,
                pagex = event.pagex,
                pagey = event.pagey,
                scroll = this.cssposition === "absolute" && !(this.scrollparent[0] !== document && $.contains(this.scrollparent[0], this.offsetparent[0])) ? this.offsetparent : this.scrollparent, scrollisrootnode = (/(html|body)/i).test(scroll[0].tagname);

            // this is another very weird special case that only happens for relative elements:
            // 1. if the css position is relative
            // 2. and the scroll parent is the document or similar to the offset parent
            // we have to refresh the relative offset during the scroll so there are no jumps
            if(this.cssposition === "relative" && !(this.scrollparent[0] !== document && this.scrollparent[0] !== this.offsetparent[0])) {
                this.offset.relative = this._getrelativeoffset();
            }

            /*
             * - position constraining -
             * constrain the position to a mix of grid, containment.
             */

            if(this.originalposition) { //if we are not dragging yet, we won't check for options

                if(this.containment) {
                    if(event.pagex - this.offset.click.left < this.containment[0]) {
                        pagex = this.containment[0] + this.offset.click.left;
                    }
                    if(event.pagey - this.offset.click.top < this.containment[1]) {
                        pagey = this.containment[1] + this.offset.click.top;
                    }
                    if(event.pagex - this.offset.click.left > this.containment[2]) {
                        pagex = this.containment[2] + this.offset.click.left;
                    }
                    if(event.pagey - this.offset.click.top > this.containment[3]) {
                        pagey = this.containment[3] + this.offset.click.top;
                    }
                }

                if(o.grid) {
                    top = this.originalpagey + math.round((pagey - this.originalpagey) / o.grid[1]) * o.grid[1];
                    pagey = this.containment ? ( (top - this.offset.click.top >= this.containment[1] && top - this.offset.click.top <= this.containment[3]) ? top : ((top - this.offset.click.top >= this.containment[1]) ? top - o.grid[1] : top + o.grid[1])) : top;

                    left = this.originalpagex + math.round((pagex - this.originalpagex) / o.grid[0]) * o.grid[0];
                    pagex = this.containment ? ( (left - this.offset.click.left >= this.containment[0] && left - this.offset.click.left <= this.containment[2]) ? left : ((left - this.offset.click.left >= this.containment[0]) ? left - o.grid[0] : left + o.grid[0])) : left;
                }

            }

            return {
                top: (
                    pagey -																// the absolute mouse position
                    this.offset.click.top -													// click offset (relative to the element)
                    this.offset.relative.top	-											// only for relative positioned nodes: relative offset from element to offset parent
                    this.offset.parent.top +												// the offsetparent's offset without borders (offset + border)
                    ( ( this.cssposition === "fixed" ? -this.scrollparent.scrolltop() : ( scrollisrootnode ? 0 : scroll.scrolltop() ) ))
                    ),
                left: (
                    pagex -																// the absolute mouse position
                    this.offset.click.left -												// click offset (relative to the element)
                    this.offset.relative.left	-											// only for relative positioned nodes: relative offset from element to offset parent
                    this.offset.parent.left +												// the offsetparent's offset without borders (offset + border)
                    ( ( this.cssposition === "fixed" ? -this.scrollparent.scrollleft() : scrollisrootnode ? 0 : scroll.scrollleft() ))
                    )
            };

        },

        _rearrange: function(event, i, a, hardrefresh) {

            a ? a[0].appendchild(this.placeholder[0]) : i.item[0].parentnode.insertbefore(this.placeholder[0], (this.direction === "down" ? i.item[0] : i.item[0].nextsibling));

            //various things done here to improve the performance:
            // 1. we create a settimeout, that calls refreshpositions
            // 2. on the instance, we have a counter variable, that get's higher after every append
            // 3. on the local scope, we copy the counter variable, and check in the timeout, if it's still the same
            // 4. this lets only the last addition to the timeout stack through
            this.counter = this.counter ? ++this.counter : 1;
            var counter = this.counter;

            this._delay(function() {
                if(counter === this.counter) {
                    this.refreshpositions(!hardrefresh); //precompute after each dom insertion, not on mousemove
                }
            });

        },

        _clear: function(event, nopropagation) {

            this.reverting = false;
            // we delay all events that have to be triggered to after the point where the placeholder has been removed and
            // everything else normalized again
            var i,
                delayedtriggers = [];

            // we first have to update the dom position of the actual currentitem
            // note: don't do it if the current item is already removed (by a user), or it gets reappended (see #4088)
            if(!this._nofinalsort && this.currentitem.parent().length) {
                this.placeholder.before(this.currentitem);
            }
            this._nofinalsort = null;

            if(this.helper[0] === this.currentitem[0]) {
                for(i in this._storedcss) {
                    if(this._storedcss[i] === "auto" || this._storedcss[i] === "static") {
                        this._storedcss[i] = "";
                    }
                }
                this.currentitem.css(this._storedcss).removeclass("ui-sortable-helper");
            } else {
                this.currentitem.show();
            }

            if(this.fromoutside && !nopropagation) {
                delayedtriggers.push(function(event) { this._trigger("receive", event, this._uihash(this.fromoutside)); });
            }
            if((this.fromoutside || this.domposition.prev !== this.currentitem.prev().not(".ui-sortable-helper")[0] || this.domposition.parent !== this.currentitem.parent()[0]) && !nopropagation) {
                delayedtriggers.push(function(event) { this._trigger("update", event, this._uihash()); }); //trigger update callback if the dom position has changed
            }

            // check if the items container has changed and trigger appropriate
            // events.
            if (this !== this.currentcontainer) {
                if(!nopropagation) {
                    delayedtriggers.push(function(event) { this._trigger("remove", event, this._uihash()); });
                    delayedtriggers.push((function(c) { return function(event) { c._trigger("receive", event, this._uihash(this)); };  }).call(this, this.currentcontainer));
                    delayedtriggers.push((function(c) { return function(event) { c._trigger("update", event, this._uihash(this));  }; }).call(this, this.currentcontainer));
                }
            }


            //post events to containers
            function delayevent( type, instance, container ) {
                return function( event ) {
                    container._trigger( type, event, instance._uihash( instance ) );
                };
            }
            for (i = this.containers.length - 1; i >= 0; i--){
                if (!nopropagation) {
                    delayedtriggers.push( delayevent( "deactivate", this, this.containers[ i ] ) );
                }
                if(this.containers[i].containercache.over) {
                    delayedtriggers.push( delayevent( "out", this, this.containers[ i ] ) );
                    this.containers[i].containercache.over = 0;
                }
            }

            //do what was originally in plugins
            if ( this.storedcursor ) {
                this.document.find( "body" ).css( "cursor", this.storedcursor );
                this.storedstylesheet.remove();
            }
            if(this._storedopacity) {
                this.helper.css("opacity", this._storedopacity);
            }
            if(this._storedzindex) {
                this.helper.css("zindex", this._storedzindex === "auto" ? "" : this._storedzindex);
            }

            this.dragging = false;

            if(!nopropagation) {
                this._trigger("beforestop", event, this._uihash());
            }

            //$(this.placeholder[0]).remove(); would have been the jquery way - unfortunately, it unbinds all events from the original node!
            this.placeholder[0].parentnode.removechild(this.placeholder[0]);

            if ( !this.cancelhelperremoval ) {
                if ( this.helper[ 0 ] !== this.currentitem[ 0 ] ) {
                    this.helper.remove();
                }
                this.helper = null;
            }

            if(!nopropagation) {
                for (i=0; i < delayedtriggers.length; i++) {
                    delayedtriggers[i].call(this, event);
                } //trigger all delayed events
                this._trigger("stop", event, this._uihash());
            }

            this.fromoutside = false;
            return !this.cancelhelperremoval;

        },

        _trigger: function() {
            if ($.widget.prototype._trigger.apply(this, arguments) === false) {
                this.cancel();
            }
        },

        _uihash: function(_inst) {
            var inst = _inst || this;
            return {
                helper: inst.helper,
                placeholder: inst.placeholder || $([]),
                position: inst.position,
                originalposition: inst.originalposition,
                offset: inst.positionabs,
                item: inst.currentitem,
                sender: _inst ? _inst.element : null
            };
        }

    });


    /*!
     * jquery ui spinner 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/spinner/
     */


    function spinner_modifier( fn ) {
        return function() {
            var previous = this.element.val();
            fn.apply( this, arguments );
            this._refresh();
            if ( previous !== this.element.val() ) {
                this._trigger( "change" );
            }
        };
    }

    var spinner = $.widget( "ui.spinner", {
        version: "1.11.2",
        defaultelement: "<input>",
        widgeteventprefix: "spin",
        options: {
            culture: null,
            icons: {
                down: "ui-icon-triangle-1-s",
                up: "ui-icon-triangle-1-n"
            },
            incremental: true,
            max: null,
            min: null,
            numberformat: null,
            page: 10,
            step: 1,

            change: null,
            spin: null,
            start: null,
            stop: null
        },

        _create: function() {
            // handle string values that need to be parsed
            this._setoption( "max", this.options.max );
            this._setoption( "min", this.options.min );
            this._setoption( "step", this.options.step );

            // only format if there is a value, prevents the field from being marked
            // as invalid in firefox, see #9573.
            if ( this.value() !== "" ) {
                // format the value, but don't constrain.
                this._value( this.element.val(), true );
            }

            this._draw();
            this._on( this._events );
            this._refresh();

            // turning off autocomplete prevents the browser from remembering the
            // value when navigating through history, so we re-enable autocomplete
            // if the page is unloaded before the widget is destroyed. #7790
            this._on( this.window, {
                beforeunload: function() {
                    this.element.removeattr( "autocomplete" );
                }
            });
        },

        _getcreateoptions: function() {
            var options = {},
                element = this.element;

            $.each( [ "min", "max", "step" ], function( i, option ) {
                var value = element.attr( option );
                if ( value !== undefined && value.length ) {
                    options[ option ] = value;
                }
            });

            return options;
        },

        _events: {
            keydown: function( event ) {
                if ( this._start( event ) && this._keydown( event ) ) {
                    event.preventdefault();
                }
            },
            keyup: "_stop",
            focus: function() {
                this.previous = this.element.val();
            },
            blur: function( event ) {
                if ( this.cancelblur ) {
                    delete this.cancelblur;
                    return;
                }

                this._stop();
                this._refresh();
                if ( this.previous !== this.element.val() ) {
                    this._trigger( "change", event );
                }
            },
            mousewheel: function( event, delta ) {
                if ( !delta ) {
                    return;
                }
                if ( !this.spinning && !this._start( event ) ) {
                    return false;
                }

                this._spin( (delta > 0 ? 1 : -1) * this.options.step, event );
                cleartimeout( this.mousewheeltimer );
                this.mousewheeltimer = this._delay(function() {
                    if ( this.spinning ) {
                        this._stop( event );
                    }
                }, 100 );
                event.preventdefault();
            },
            "mousedown .ui-spinner-button": function( event ) {
                var previous;

                // we never want the buttons to have focus; whenever the user is
                // interacting with the spinner, the focus should be on the input.
                // if the input is focused then this.previous is properly set from
                // when the input first received focus. if the input is not focused
                // then we need to set this.previous based on the value before spinning.
                previous = this.element[0] === this.document[0].activeelement ?
                    this.previous : this.element.val();
                function checkfocus() {
                    var isactive = this.element[0] === this.document[0].activeelement;
                    if ( !isactive ) {
                        this.element.focus();
                        this.previous = previous;
                        // support: ie
                        // ie sets focus asynchronously, so we need to check if focus
                        // moved off of the input because the user clicked on the button.
                        this._delay(function() {
                            this.previous = previous;
                        });
                    }
                }

                // ensure focus is on (or stays on) the text field
                event.preventdefault();
                checkfocus.call( this );

                // support: ie
                // ie doesn't prevent moving focus even with event.preventdefault()
                // so we set a flag to know when we should ignore the blur event
                // and check (again) if focus moved off of the input.
                this.cancelblur = true;
                this._delay(function() {
                    delete this.cancelblur;
                    checkfocus.call( this );
                });

                if ( this._start( event ) === false ) {
                    return;
                }

                this._repeat( null, $( event.currenttarget ).hasclass( "ui-spinner-up" ) ? 1 : -1, event );
            },
            "mouseup .ui-spinner-button": "_stop",
            "mouseenter .ui-spinner-button": function( event ) {
                // button will add ui-state-active if mouse was down while mouseleave and kept down
                if ( !$( event.currenttarget ).hasclass( "ui-state-active" ) ) {
                    return;
                }

                if ( this._start( event ) === false ) {
                    return false;
                }
                this._repeat( null, $( event.currenttarget ).hasclass( "ui-spinner-up" ) ? 1 : -1, event );
            },
            // todo: do we really want to consider this a stop?
            // shouldn't we just stop the repeater and wait until mouseup before
            // we trigger the stop event?
            "mouseleave .ui-spinner-button": "_stop"
        },

        _draw: function() {
            var uispinner = this.uispinner = this.element
                .addclass( "ui-spinner-input" )
                .attr( "autocomplete", "off" )
                .wrap( this._uispinnerhtml() )
                .parent()
                // add buttons
                .append( this._buttonhtml() );

            this.element.attr( "role", "spinbutton" );

            // button bindings
            this.buttons = uispinner.find( ".ui-spinner-button" )
                .attr( "tabindex", -1 )
                .button()
                .removeclass( "ui-corner-all" );

            // ie 6 doesn't understand height: 50% for the buttons
            // unless the wrapper has an explicit height
            if ( this.buttons.height() > math.ceil( uispinner.height() * 0.5 ) &&
                uispinner.height() > 0 ) {
                uispinner.height( uispinner.height() );
            }

            // disable spinner if element was already disabled
            if ( this.options.disabled ) {
                this.disable();
            }
        },

        _keydown: function( event ) {
            var options = this.options,
                keycode = $.ui.keycode;

            switch ( event.keycode ) {
                case keycode.up:
                    this._repeat( null, 1, event );
                    return true;
                case keycode.down:
                    this._repeat( null, -1, event );
                    return true;
                case keycode.page_up:
                    this._repeat( null, options.page, event );
                    return true;
                case keycode.page_down:
                    this._repeat( null, -options.page, event );
                    return true;
            }

            return false;
        },

        _uispinnerhtml: function() {
            return "<span class='ui-spinner ui-widget ui-widget-content ui-corner-all'></span>";
        },

        _buttonhtml: function() {
            return "" +
                "<a class='ui-spinner-button ui-spinner-up ui-corner-tr'>" +
                "<span class='ui-icon " + this.options.icons.up + "'>&#9650;</span>" +
                "</a>" +
                "<a class='ui-spinner-button ui-spinner-down ui-corner-br'>" +
                "<span class='ui-icon " + this.options.icons.down + "'>&#9660;</span>" +
                "</a>";
        },

        _start: function( event ) {
            if ( !this.spinning && this._trigger( "start", event ) === false ) {
                return false;
            }

            if ( !this.counter ) {
                this.counter = 1;
            }
            this.spinning = true;
            return true;
        },

        _repeat: function( i, steps, event ) {
            i = i || 500;

            cleartimeout( this.timer );
            this.timer = this._delay(function() {
                this._repeat( 40, steps, event );
            }, i );

            this._spin( steps * this.options.step, event );
        },

        _spin: function( step, event ) {
            var value = this.value() || 0;

            if ( !this.counter ) {
                this.counter = 1;
            }

            value = this._adjustvalue( value + step * this._increment( this.counter ) );

            if ( !this.spinning || this._trigger( "spin", event, { value: value } ) !== false) {
                this._value( value );
                this.counter++;
            }
        },

        _increment: function( i ) {
            var incremental = this.options.incremental;

            if ( incremental ) {
                return $.isfunction( incremental ) ?
                    incremental( i ) :
                    math.floor( i * i * i / 50000 - i * i / 500 + 17 * i / 200 + 1 );
            }

            return 1;
        },

        _precision: function() {
            var precision = this._precisionof( this.options.step );
            if ( this.options.min !== null ) {
                precision = math.max( precision, this._precisionof( this.options.min ) );
            }
            return precision;
        },

        _precisionof: function( num ) {
            var str = num.tostring(),
                decimal = str.indexof( "." );
            return decimal === -1 ? 0 : str.length - decimal - 1;
        },

        _adjustvalue: function( value ) {
            var base, abovemin,
                options = this.options;

            // make sure we're at a valid step
            // - find out where we are relative to the base (min or 0)
            base = options.min !== null ? options.min : 0;
            abovemin = value - base;
            // - round to the nearest step
            abovemin = math.round(abovemin / options.step) * options.step;
            // - rounding is based on 0, so adjust back to our base
            value = base + abovemin;

            // fix precision from bad js floating point math
            value = parsefloat( value.tofixed( this._precision() ) );

            // clamp the value
            if ( options.max !== null && value > options.max) {
                return options.max;
            }
            if ( options.min !== null && value < options.min ) {
                return options.min;
            }

            return value;
        },

        _stop: function( event ) {
            if ( !this.spinning ) {
                return;
            }

            cleartimeout( this.timer );
            cleartimeout( this.mousewheeltimer );
            this.counter = 0;
            this.spinning = false;
            this._trigger( "stop", event );
        },

        _setoption: function( key, value ) {
            if ( key === "culture" || key === "numberformat" ) {
                var prevvalue = this._parse( this.element.val() );
                this.options[ key ] = value;
                this.element.val( this._format( prevvalue ) );
                return;
            }

            if ( key === "max" || key === "min" || key === "step" ) {
                if ( typeof value === "string" ) {
                    value = this._parse( value );
                }
            }
            if ( key === "icons" ) {
                this.buttons.first().find( ".ui-icon" )
                    .removeclass( this.options.icons.up )
                    .addclass( value.up );
                this.buttons.last().find( ".ui-icon" )
                    .removeclass( this.options.icons.down )
                    .addclass( value.down );
            }

            this._super( key, value );

            if ( key === "disabled" ) {
                this.widget().toggleclass( "ui-state-disabled", !!value );
                this.element.prop( "disabled", !!value );
                this.buttons.button( value ? "disable" : "enable" );
            }
        },

        _setoptions: spinner_modifier(function( options ) {
            this._super( options );
        }),

        _parse: function( val ) {
            if ( typeof val === "string" && val !== "" ) {
                val = window.globalize && this.options.numberformat ?
                    globalize.parsefloat( val, 10, this.options.culture ) : +val;
            }
            return val === "" || isnan( val ) ? null : val;
        },

        _format: function( value ) {
            if ( value === "" ) {
                return "";
            }
            return window.globalize && this.options.numberformat ?
                globalize.format( value, this.options.numberformat, this.options.culture ) :
                value;
        },

        _refresh: function() {
            this.element.attr({
                "aria-valuemin": this.options.min,
                "aria-valuemax": this.options.max,
                // todo: what should we do with values that can't be parsed?
                "aria-valuenow": this._parse( this.element.val() )
            });
        },

        isvalid: function() {
            var value = this.value();

            // null is invalid
            if ( value === null ) {
                return false;
            }

            // if value gets adjusted, it's invalid
            return value === this._adjustvalue( value );
        },

        // update the value without triggering change
        _value: function( value, allowany ) {
            var parsed;
            if ( value !== "" ) {
                parsed = this._parse( value );
                if ( parsed !== null ) {
                    if ( !allowany ) {
                        parsed = this._adjustvalue( parsed );
                    }
                    value = this._format( parsed );
                }
            }
            this.element.val( value );
            this._refresh();
        },

        _destroy: function() {
            this.element
                .removeclass( "ui-spinner-input" )
                .prop( "disabled", false )
                .removeattr( "autocomplete" )
                .removeattr( "role" )
                .removeattr( "aria-valuemin" )
                .removeattr( "aria-valuemax" )
                .removeattr( "aria-valuenow" );
            this.uispinner.replacewith( this.element );
        },

        stepup: spinner_modifier(function( steps ) {
            this._stepup( steps );
        }),
        _stepup: function( steps ) {
            if ( this._start() ) {
                this._spin( (steps || 1) * this.options.step );
                this._stop();
            }
        },

        stepdown: spinner_modifier(function( steps ) {
            this._stepdown( steps );
        }),
        _stepdown: function( steps ) {
            if ( this._start() ) {
                this._spin( (steps || 1) * -this.options.step );
                this._stop();
            }
        },

        pageup: spinner_modifier(function( pages ) {
            this._stepup( (pages || 1) * this.options.page );
        }),

        pagedown: spinner_modifier(function( pages ) {
            this._stepdown( (pages || 1) * this.options.page );
        }),

        value: function( newval ) {
            if ( !arguments.length ) {
                return this._parse( this.element.val() );
            }
            spinner_modifier( this._value ).call( this, newval );
        },

        widget: function() {
            return this.uispinner;
        }
    });


    /*!
     * jquery ui tabs 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/tabs/
     */


    var tabs = $.widget( "ui.tabs", {
        version: "1.11.2",
        delay: 300,
        options: {
            active: null,
            collapsible: false,
            event: "click",
            heightstyle: "content",
            hide: null,
            show: null,

            // callbacks
            activate: null,
            beforeactivate: null,
            beforeload: null,
            load: null
        },

        _islocal: (function() {
            var rhash = /#.*$/;

            return function( anchor ) {
                var anchorurl, locationurl;

                // support: ie7
                // ie7 doesn't normalize the href property when set via script (#9317)
                anchor = anchor.clonenode( false );

                anchorurl = anchor.href.replace( rhash, "" );
                locationurl = location.href.replace( rhash, "" );

                // decoding may throw an error if the url isn't utf-8 (#9518)
                try {
                    anchorurl = decodeuricomponent( anchorurl );
                } catch ( error ) {}
                try {
                    locationurl = decodeuricomponent( locationurl );
                } catch ( error ) {}

                return anchor.hash.length > 1 && anchorurl === locationurl;
            };
        })(),

        _create: function() {
            var that = this,
                options = this.options;

            this.running = false;

            this.element
                .addclass( "ui-tabs ui-widget ui-widget-content ui-corner-all" )
                .toggleclass( "ui-tabs-collapsible", options.collapsible );

            this._processtabs();
            options.active = this._initialactive();

            // take disabling tabs via class attribute from html
            // into account and update option properly.
            if ( $.isarray( options.disabled ) ) {
                options.disabled = $.unique( options.disabled.concat(
                    $.map( this.tabs.filter( ".ui-state-disabled" ), function( li ) {
                        return that.tabs.index( li );
                    })
                ) ).sort();
            }

            // check for length avoids error when initializing empty list
            if ( this.options.active !== false && this.anchors.length ) {
                this.active = this._findactive( options.active );
            } else {
                this.active = $();
            }

            this._refresh();

            if ( this.active.length ) {
                this.load( options.active );
            }
        },

        _initialactive: function() {
            var active = this.options.active,
                collapsible = this.options.collapsible,
                locationhash = location.hash.substring( 1 );

            if ( active === null ) {
                // check the fragment identifier in the url
                if ( locationhash ) {
                    this.tabs.each(function( i, tab ) {
                        if ( $( tab ).attr( "aria-controls" ) === locationhash ) {
                            active = i;
                            return false;
                        }
                    });
                }

                // check for a tab marked active via a class
                if ( active === null ) {
                    active = this.tabs.index( this.tabs.filter( ".ui-tabs-active" ) );
                }

                // no active tab, set to false
                if ( active === null || active === -1 ) {
                    active = this.tabs.length ? 0 : false;
                }
            }

            // handle numbers: negative, out of range
            if ( active !== false ) {
                active = this.tabs.index( this.tabs.eq( active ) );
                if ( active === -1 ) {
                    active = collapsible ? false : 0;
                }
            }

            // don't allow collapsible: false and active: false
            if ( !collapsible && active === false && this.anchors.length ) {
                active = 0;
            }

            return active;
        },

        _getcreateeventdata: function() {
            return {
                tab: this.active,
                panel: !this.active.length ? $() : this._getpanelfortab( this.active )
            };
        },

        _tabkeydown: function( event ) {
            var focusedtab = $( this.document[0].activeelement ).closest( "li" ),
                selectedindex = this.tabs.index( focusedtab ),
                goingforward = true;

            if ( this._handlepagenav( event ) ) {
                return;
            }

            switch ( event.keycode ) {
                case $.ui.keycode.right:
                case $.ui.keycode.down:
                    selectedindex++;
                    break;
                case $.ui.keycode.up:
                case $.ui.keycode.left:
                    goingforward = false;
                    selectedindex--;
                    break;
                case $.ui.keycode.end:
                    selectedindex = this.anchors.length - 1;
                    break;
                case $.ui.keycode.home:
                    selectedindex = 0;
                    break;
                case $.ui.keycode.space:
                    // activate only, no collapsing
                    event.preventdefault();
                    cleartimeout( this.activating );
                    this._activate( selectedindex );
                    return;
                case $.ui.keycode.enter:
                    // toggle (cancel delayed activation, allow collapsing)
                    event.preventdefault();
                    cleartimeout( this.activating );
                    // determine if we should collapse or activate
                    this._activate( selectedindex === this.options.active ? false : selectedindex );
                    return;
                default:
                    return;
            }

            // focus the appropriate tab, based on which key was pressed
            event.preventdefault();
            cleartimeout( this.activating );
            selectedindex = this._focusnexttab( selectedindex, goingforward );

            // navigating with control key will prevent automatic activation
            if ( !event.ctrlkey ) {
                // update aria-selected immediately so that at think the tab is already selected.
                // otherwise at may confuse the user by stating that they need to activate the tab,
                // but the tab will already be activated by the time the announcement finishes.
                focusedtab.attr( "aria-selected", "false" );
                this.tabs.eq( selectedindex ).attr( "aria-selected", "true" );

                this.activating = this._delay(function() {
                    this.option( "active", selectedindex );
                }, this.delay );
            }
        },

        _panelkeydown: function( event ) {
            if ( this._handlepagenav( event ) ) {
                return;
            }

            // ctrl+up moves focus to the current tab
            if ( event.ctrlkey && event.keycode === $.ui.keycode.up ) {
                event.preventdefault();
                this.active.focus();
            }
        },

        // alt+page up/down moves focus to the previous/next tab (and activates)
        _handlepagenav: function( event ) {
            if ( event.altkey && event.keycode === $.ui.keycode.page_up ) {
                this._activate( this._focusnexttab( this.options.active - 1, false ) );
                return true;
            }
            if ( event.altkey && event.keycode === $.ui.keycode.page_down ) {
                this._activate( this._focusnexttab( this.options.active + 1, true ) );
                return true;
            }
        },

        _findnexttab: function( index, goingforward ) {
            var lasttabindex = this.tabs.length - 1;

            function constrain() {
                if ( index > lasttabindex ) {
                    index = 0;
                }
                if ( index < 0 ) {
                    index = lasttabindex;
                }
                return index;
            }

            while ( $.inarray( constrain(), this.options.disabled ) !== -1 ) {
                index = goingforward ? index + 1 : index - 1;
            }

            return index;
        },

        _focusnexttab: function( index, goingforward ) {
            index = this._findnexttab( index, goingforward );
            this.tabs.eq( index ).focus();
            return index;
        },

        _setoption: function( key, value ) {
            if ( key === "active" ) {
                // _activate() will handle invalid values and update this.options
                this._activate( value );
                return;
            }

            if ( key === "disabled" ) {
                // don't use the widget factory's disabled handling
                this._setupdisabled( value );
                return;
            }

            this._super( key, value);

            if ( key === "collapsible" ) {
                this.element.toggleclass( "ui-tabs-collapsible", value );
                // setting collapsible: false while collapsed; open first panel
                if ( !value && this.options.active === false ) {
                    this._activate( 0 );
                }
            }

            if ( key === "event" ) {
                this._setupevents( value );
            }

            if ( key === "heightstyle" ) {
                this._setupheightstyle( value );
            }
        },

        _sanitizeselector: function( hash ) {
            return hash ? hash.replace( /[!"$%&'()*+,.\/:;<=>?@\[\]\^`{|}~]/g, "\\$&" ) : "";
        },

        refresh: function() {
            var options = this.options,
                lis = this.tablist.children( ":has(a[href])" );

            // get disabled tabs from class attribute from html
            // this will get converted to a boolean if needed in _refresh()
            options.disabled = $.map( lis.filter( ".ui-state-disabled" ), function( tab ) {
                return lis.index( tab );
            });

            this._processtabs();

            // was collapsed or no tabs
            if ( options.active === false || !this.anchors.length ) {
                options.active = false;
                this.active = $();
                // was active, but active tab is gone
            } else if ( this.active.length && !$.contains( this.tablist[ 0 ], this.active[ 0 ] ) ) {
                // all remaining tabs are disabled
                if ( this.tabs.length === options.disabled.length ) {
                    options.active = false;
                    this.active = $();
                    // activate previous tab
                } else {
                    this._activate( this._findnexttab( math.max( 0, options.active - 1 ), false ) );
                }
                // was active, active tab still exists
            } else {
                // make sure active index is correct
                options.active = this.tabs.index( this.active );
            }

            this._refresh();
        },

        _refresh: function() {
            this._setupdisabled( this.options.disabled );
            this._setupevents( this.options.event );
            this._setupheightstyle( this.options.heightstyle );

            this.tabs.not( this.active ).attr({
                "aria-selected": "false",
                "aria-expanded": "false",
                tabindex: -1
            });
            this.panels.not( this._getpanelfortab( this.active ) )
                .hide()
                .attr({
                    "aria-hidden": "true"
                });

            // make sure one tab is in the tab order
            if ( !this.active.length ) {
                this.tabs.eq( 0 ).attr( "tabindex", 0 );
            } else {
                this.active
                    .addclass( "ui-tabs-active ui-state-active" )
                    .attr({
                        "aria-selected": "true",
                        "aria-expanded": "true",
                        tabindex: 0
                    });
                this._getpanelfortab( this.active )
                    .show()
                    .attr({
                        "aria-hidden": "false"
                    });
            }
        },

        _processtabs: function() {
            var that = this,
                prevtabs = this.tabs,
                prevanchors = this.anchors,
                prevpanels = this.panels;

            this.tablist = this._getlist()
                .addclass( "ui-tabs-nav ui-helper-reset ui-helper-clearfix ui-widget-header ui-corner-all" )
                .attr( "role", "tablist" )

                // prevent users from focusing disabled tabs via click
                .delegate( "> li", "mousedown" + this.eventnamespace, function( event ) {
                    if ( $( this ).is( ".ui-state-disabled" ) ) {
                        event.preventdefault();
                    }
                })

                // support: ie <9
                // preventing the default action in mousedown doesn't prevent ie
                // from focusing the element, so if the anchor gets focused, blur.
                // we don't have to worry about focusing the previously focused
                // element since clicking on a non-focusable element should focus
                // the body anyway.
                .delegate( ".ui-tabs-anchor", "focus" + this.eventnamespace, function() {
                    if ( $( this ).closest( "li" ).is( ".ui-state-disabled" ) ) {
                        this.blur();
                    }
                });

            this.tabs = this.tablist.find( "> li:has(a[href])" )
                .addclass( "ui-state-default ui-corner-top" )
                .attr({
                    role: "tab",
                    tabindex: -1
                });

            this.anchors = this.tabs.map(function() {
                return $( "a", this )[ 0 ];
            })
                .addclass( "ui-tabs-anchor" )
                .attr({
                    role: "presentation",
                    tabindex: -1
                });

            this.panels = $();

            this.anchors.each(function( i, anchor ) {
                var selector, panel, panelid,
                    anchorid = $( anchor ).uniqueid().attr( "id" ),
                    tab = $( anchor ).closest( "li" ),
                    originalariacontrols = tab.attr( "aria-controls" );

                // inline tab
                if ( that._islocal( anchor ) ) {
                    selector = anchor.hash;
                    panelid = selector.substring( 1 );
                    panel = that.element.find( that._sanitizeselector( selector ) );
                    // remote tab
                } else {
                    // if the tab doesn't already have aria-controls,
                    // generate an id by using a throw-away element
                    panelid = tab.attr( "aria-controls" ) || $( {} ).uniqueid()[ 0 ].id;
                    selector = "#" + panelid;
                    panel = that.element.find( selector );
                    if ( !panel.length ) {
                        panel = that._createpanel( panelid );
                        panel.insertafter( that.panels[ i - 1 ] || that.tablist );
                    }
                    panel.attr( "aria-live", "polite" );
                }

                if ( panel.length) {
                    that.panels = that.panels.add( panel );
                }
                if ( originalariacontrols ) {
                    tab.data( "ui-tabs-aria-controls", originalariacontrols );
                }
                tab.attr({
                    "aria-controls": panelid,
                    "aria-labelledby": anchorid
                });
                panel.attr( "aria-labelledby", anchorid );
            });

            this.panels
                .addclass( "ui-tabs-panel ui-widget-content ui-corner-bottom" )
                .attr( "role", "tabpanel" );

            // avoid memory leaks (#10056)
            if ( prevtabs ) {
                this._off( prevtabs.not( this.tabs ) );
                this._off( prevanchors.not( this.anchors ) );
                this._off( prevpanels.not( this.panels ) );
            }
        },

        // allow overriding how to find the list for rare usage scenarios (#7715)
        _getlist: function() {
            return this.tablist || this.element.find( "ol,ul" ).eq( 0 );
        },

        _createpanel: function( id ) {
            return $( "<div>" )
                .attr( "id", id )
                .addclass( "ui-tabs-panel ui-widget-content ui-corner-bottom" )
                .data( "ui-tabs-destroy", true );
        },

        _setupdisabled: function( disabled ) {
            if ( $.isarray( disabled ) ) {
                if ( !disabled.length ) {
                    disabled = false;
                } else if ( disabled.length === this.anchors.length ) {
                    disabled = true;
                }
            }

            // disable tabs
            for ( var i = 0, li; ( li = this.tabs[ i ] ); i++ ) {
                if ( disabled === true || $.inarray( i, disabled ) !== -1 ) {
                    $( li )
                        .addclass( "ui-state-disabled" )
                        .attr( "aria-disabled", "true" );
                } else {
                    $( li )
                        .removeclass( "ui-state-disabled" )
                        .removeattr( "aria-disabled" );
                }
            }

            this.options.disabled = disabled;
        },

        _setupevents: function( event ) {
            var events = {};
            if ( event ) {
                $.each( event.split(" "), function( index, eventname ) {
                    events[ eventname ] = "_eventhandler";
                });
            }

            this._off( this.anchors.add( this.tabs ).add( this.panels ) );
            // always prevent the default action, even when disabled
            this._on( true, this.anchors, {
                click: function( event ) {
                    event.preventdefault();
                }
            });
            this._on( this.anchors, events );
            this._on( this.tabs, { keydown: "_tabkeydown" } );
            this._on( this.panels, { keydown: "_panelkeydown" } );

            this._focusable( this.tabs );
            this._hoverable( this.tabs );
        },

        _setupheightstyle: function( heightstyle ) {
            var maxheight,
                parent = this.element.parent();

            if ( heightstyle === "fill" ) {
                maxheight = parent.height();
                maxheight -= this.element.outerheight() - this.element.height();

                this.element.siblings( ":visible" ).each(function() {
                    var elem = $( this ),
                        position = elem.css( "position" );

                    if ( position === "absolute" || position === "fixed" ) {
                        return;
                    }
                    maxheight -= elem.outerheight( true );
                });

                this.element.children().not( this.panels ).each(function() {
                    maxheight -= $( this ).outerheight( true );
                });

                this.panels.each(function() {
                    $( this ).height( math.max( 0, maxheight -
                        $( this ).innerheight() + $( this ).height() ) );
                })
                    .css( "overflow", "auto" );
            } else if ( heightstyle === "auto" ) {
                maxheight = 0;
                this.panels.each(function() {
                    maxheight = math.max( maxheight, $( this ).height( "" ).height() );
                }).height( maxheight );
            }
        },

        _eventhandler: function( event ) {
            var options = this.options,
                active = this.active,
                anchor = $( event.currenttarget ),
                tab = anchor.closest( "li" ),
                clickedisactive = tab[ 0 ] === active[ 0 ],
                collapsing = clickedisactive && options.collapsible,
                toshow = collapsing ? $() : this._getpanelfortab( tab ),
                tohide = !active.length ? $() : this._getpanelfortab( active ),
                eventdata = {
                    oldtab: active,
                    oldpanel: tohide,
                    newtab: collapsing ? $() : tab,
                    newpanel: toshow
                };

            event.preventdefault();

            if ( tab.hasclass( "ui-state-disabled" ) ||
                // tab is already loading
                tab.hasclass( "ui-tabs-loading" ) ||
                // can't switch durning an animation
                this.running ||
                // click on active header, but not collapsible
                ( clickedisactive && !options.collapsible ) ||
                // allow canceling activation
                ( this._trigger( "beforeactivate", event, eventdata ) === false ) ) {
                return;
            }

            options.active = collapsing ? false : this.tabs.index( tab );

            this.active = clickedisactive ? $() : tab;
            if ( this.xhr ) {
                this.xhr.abort();
            }

            if ( !tohide.length && !toshow.length ) {
                $.error( "jquery ui tabs: mismatching fragment identifier." );
            }

            if ( toshow.length ) {
                this.load( this.tabs.index( tab ), event );
            }
            this._toggle( event, eventdata );
        },

        // handles show/hide for selecting tabs
        _toggle: function( event, eventdata ) {
            var that = this,
                toshow = eventdata.newpanel,
                tohide = eventdata.oldpanel;

            this.running = true;

            function complete() {
                that.running = false;
                that._trigger( "activate", event, eventdata );
            }

            function show() {
                eventdata.newtab.closest( "li" ).addclass( "ui-tabs-active ui-state-active" );

                if ( toshow.length && that.options.show ) {
                    that._show( toshow, that.options.show, complete );
                } else {
                    toshow.show();
                    complete();
                }
            }

            // start out by hiding, then showing, then completing
            if ( tohide.length && this.options.hide ) {
                this._hide( tohide, this.options.hide, function() {
                    eventdata.oldtab.closest( "li" ).removeclass( "ui-tabs-active ui-state-active" );
                    show();
                });
            } else {
                eventdata.oldtab.closest( "li" ).removeclass( "ui-tabs-active ui-state-active" );
                tohide.hide();
                show();
            }

            tohide.attr( "aria-hidden", "true" );
            eventdata.oldtab.attr({
                "aria-selected": "false",
                "aria-expanded": "false"
            });
            // if we're switching tabs, remove the old tab from the tab order.
            // if we're opening from collapsed state, remove the previous tab from the tab order.
            // if we're collapsing, then keep the collapsing tab in the tab order.
            if ( toshow.length && tohide.length ) {
                eventdata.oldtab.attr( "tabindex", -1 );
            } else if ( toshow.length ) {
                this.tabs.filter(function() {
                    return $( this ).attr( "tabindex" ) === 0;
                })
                    .attr( "tabindex", -1 );
            }

            toshow.attr( "aria-hidden", "false" );
            eventdata.newtab.attr({
                "aria-selected": "true",
                "aria-expanded": "true",
                tabindex: 0
            });
        },

        _activate: function( index ) {
            var anchor,
                active = this._findactive( index );

            // trying to activate the already active panel
            if ( active[ 0 ] === this.active[ 0 ] ) {
                return;
            }

            // trying to collapse, simulate a click on the current active header
            if ( !active.length ) {
                active = this.active;
            }

            anchor = active.find( ".ui-tabs-anchor" )[ 0 ];
            this._eventhandler({
                target: anchor,
                currenttarget: anchor,
                preventdefault: $.noop
            });
        },

        _findactive: function( index ) {
            return index === false ? $() : this.tabs.eq( index );
        },

        _getindex: function( index ) {
            // meta-function to give users option to provide a href string instead of a numerical index.
            if ( typeof index === "string" ) {
                index = this.anchors.index( this.anchors.filter( "[href$='" + index + "']" ) );
            }

            return index;
        },

        _destroy: function() {
            if ( this.xhr ) {
                this.xhr.abort();
            }

            this.element.removeclass( "ui-tabs ui-widget ui-widget-content ui-corner-all ui-tabs-collapsible" );

            this.tablist
                .removeclass( "ui-tabs-nav ui-helper-reset ui-helper-clearfix ui-widget-header ui-corner-all" )
                .removeattr( "role" );

            this.anchors
                .removeclass( "ui-tabs-anchor" )
                .removeattr( "role" )
                .removeattr( "tabindex" )
                .removeuniqueid();

            this.tablist.unbind( this.eventnamespace );

            this.tabs.add( this.panels ).each(function() {
                if ( $.data( this, "ui-tabs-destroy" ) ) {
                    $( this ).remove();
                } else {
                    $( this )
                        .removeclass( "ui-state-default ui-state-active ui-state-disabled " +
                            "ui-corner-top ui-corner-bottom ui-widget-content ui-tabs-active ui-tabs-panel" )
                        .removeattr( "tabindex" )
                        .removeattr( "aria-live" )
                        .removeattr( "aria-busy" )
                        .removeattr( "aria-selected" )
                        .removeattr( "aria-labelledby" )
                        .removeattr( "aria-hidden" )
                        .removeattr( "aria-expanded" )
                        .removeattr( "role" );
                }
            });

            this.tabs.each(function() {
                var li = $( this ),
                    prev = li.data( "ui-tabs-aria-controls" );
                if ( prev ) {
                    li
                        .attr( "aria-controls", prev )
                        .removedata( "ui-tabs-aria-controls" );
                } else {
                    li.removeattr( "aria-controls" );
                }
            });

            this.panels.show();

            if ( this.options.heightstyle !== "content" ) {
                this.panels.css( "height", "" );
            }
        },

        enable: function( index ) {
            var disabled = this.options.disabled;
            if ( disabled === false ) {
                return;
            }

            if ( index === undefined ) {
                disabled = false;
            } else {
                index = this._getindex( index );
                if ( $.isarray( disabled ) ) {
                    disabled = $.map( disabled, function( num ) {
                        return num !== index ? num : null;
                    });
                } else {
                    disabled = $.map( this.tabs, function( li, num ) {
                        return num !== index ? num : null;
                    });
                }
            }
            this._setupdisabled( disabled );
        },

        disable: function( index ) {
            var disabled = this.options.disabled;
            if ( disabled === true ) {
                return;
            }

            if ( index === undefined ) {
                disabled = true;
            } else {
                index = this._getindex( index );
                if ( $.inarray( index, disabled ) !== -1 ) {
                    return;
                }
                if ( $.isarray( disabled ) ) {
                    disabled = $.merge( [ index ], disabled ).sort();
                } else {
                    disabled = [ index ];
                }
            }
            this._setupdisabled( disabled );
        },

        load: function( index, event ) {
            index = this._getindex( index );
            var that = this,
                tab = this.tabs.eq( index ),
                anchor = tab.find( ".ui-tabs-anchor" ),
                panel = this._getpanelfortab( tab ),
                eventdata = {
                    tab: tab,
                    panel: panel
                };

            // not remote
            if ( this._islocal( anchor[ 0 ] ) ) {
                return;
            }

            this.xhr = $.ajax( this._ajaxsettings( anchor, event, eventdata ) );

            // support: jquery <1.8
            // jquery <1.8 returns false if the request is canceled in beforesend,
            // but as of 1.8, $.ajax() always returns a jqxhr object.
            if ( this.xhr && this.xhr.statustext !== "canceled" ) {
                tab.addclass( "ui-tabs-loading" );
                panel.attr( "aria-busy", "true" );

                this.xhr
                    .success(function( response ) {
                        // support: jquery <1.8
                        // http://bugs.jquery.com/ticket/11778
                        settimeout(function() {
                            panel.html( response );
                            that._trigger( "load", event, eventdata );
                        }, 1 );
                    })
                    .complete(function( jqxhr, status ) {
                        // support: jquery <1.8
                        // http://bugs.jquery.com/ticket/11778
                        settimeout(function() {
                            if ( status === "abort" ) {
                                that.panels.stop( false, true );
                            }

                            tab.removeclass( "ui-tabs-loading" );
                            panel.removeattr( "aria-busy" );

                            if ( jqxhr === that.xhr ) {
                                delete that.xhr;
                            }
                        }, 1 );
                    });
            }
        },

        _ajaxsettings: function( anchor, event, eventdata ) {
            var that = this;
            return {
                url: anchor.attr( "href" ),
                beforesend: function( jqxhr, settings ) {
                    return that._trigger( "beforeload", event,
                        $.extend( { jqxhr: jqxhr, ajaxsettings: settings }, eventdata ) );
                }
            };
        },

        _getpanelfortab: function( tab ) {
            var id = $( tab ).attr( "aria-controls" );
            return this.element.find( this._sanitizeselector( "#" + id ) );
        }
    });


    /*!
     * jquery ui tooltip 1.11.2
     * http://jqueryui.com
     *
     * copyright 2014 jquery foundation and other contributors
     * released under the mit license.
     * http://jquery.org/license
     *
     * http://api.jqueryui.com/tooltip/
     */


    var tooltip = $.widget( "ui.tooltip", {
        version: "1.11.2",
        options: {
            content: function() {
                // support: ie<9, opera in jquery <1.7
                // .text() can't accept undefined, so coerce to a string
                var title = $( this ).attr( "title" ) || "";
                // escape title, since we're going from an attribute to raw html
                return $( "<a>" ).text( title ).html();
            },
            hide: true,
            // disabled elements have inconsistent behavior across browsers (#8661)
            items: "[title]:not([disabled])",
            position: {
                my: "left top+15",
                at: "left bottom",
                collision: "flipfit flip"
            },
            show: true,
            tooltipclass: null,
            track: false,

            // callbacks
            close: null,
            open: null
        },

        _adddescribedby: function( elem, id ) {
            var describedby = (elem.attr( "aria-describedby" ) || "").split( /\s+/ );
            describedby.push( id );
            elem
                .data( "ui-tooltip-id", id )
                .attr( "aria-describedby", $.trim( describedby.join( " " ) ) );
        },

        _removedescribedby: function( elem ) {
            var id = elem.data( "ui-tooltip-id" ),
                describedby = (elem.attr( "aria-describedby" ) || "").split( /\s+/ ),
                index = $.inarray( id, describedby );

            if ( index !== -1 ) {
                describedby.splice( index, 1 );
            }

            elem.removedata( "ui-tooltip-id" );
            describedby = $.trim( describedby.join( " " ) );
            if ( describedby ) {
                elem.attr( "aria-describedby", describedby );
            } else {
                elem.removeattr( "aria-describedby" );
            }
        },

        _create: function() {
            this._on({
                mouseover: "open",
                focusin: "open"
            });

            // ids of generated tooltips, needed for destroy
            this.tooltips = {};

            // ids of parent tooltips where we removed the title attribute
            this.parents = {};

            if ( this.options.disabled ) {
                this._disable();
            }

            // append the aria-live region so tooltips announce correctly
            this.liveregion = $( "<div>" )
                .attr({
                    role: "log",
                    "aria-live": "assertive",
                    "aria-relevant": "additions"
                })
                .addclass( "ui-helper-hidden-accessible" )
                .appendto( this.document[ 0 ].body );
        },

        _setoption: function( key, value ) {
            var that = this;

            if ( key === "disabled" ) {
                this[ value ? "_disable" : "_enable" ]();
                this.options[ key ] = value;
                // disable element style changes
                return;
            }

            this._super( key, value );

            if ( key === "content" ) {
                $.each( this.tooltips, function( id, tooltipdata ) {
                    that._updatecontent( tooltipdata.element );
                });
            }
        },

        _disable: function() {
            var that = this;

            // close open tooltips
            $.each( this.tooltips, function( id, tooltipdata ) {
                var event = $.event( "blur" );
                event.target = event.currenttarget = tooltipdata.element[ 0 ];
                that.close( event, true );
            });

            // remove title attributes to prevent native tooltips
            this.element.find( this.options.items ).addback().each(function() {
                var element = $( this );
                if ( element.is( "[title]" ) ) {
                    element
                        .data( "ui-tooltip-title", element.attr( "title" ) )
                        .removeattr( "title" );
                }
            });
        },

        _enable: function() {
            // restore title attributes
            this.element.find( this.options.items ).addback().each(function() {
                var element = $( this );
                if ( element.data( "ui-tooltip-title" ) ) {
                    element.attr( "title", element.data( "ui-tooltip-title" ) );
                }
            });
        },

        open: function( event ) {
            var that = this,
                target = $( event ? event.target : this.element )
                    // we need closest here due to mouseover bubbling,
                    // but always pointing at the same event target
                    .closest( this.options.items );

            // no element to show a tooltip for or the tooltip is already open
            if ( !target.length || target.data( "ui-tooltip-id" ) ) {
                return;
            }

            if ( target.attr( "title" ) ) {
                target.data( "ui-tooltip-title", target.attr( "title" ) );
            }

            target.data( "ui-tooltip-open", true );

            // kill parent tooltips, custom or native, for hover
            if ( event && event.type === "mouseover" ) {
                target.parents().each(function() {
                    var parent = $( this ),
                        blurevent;
                    if ( parent.data( "ui-tooltip-open" ) ) {
                        blurevent = $.event( "blur" );
                        blurevent.target = blurevent.currenttarget = this;
                        that.close( blurevent, true );
                    }
                    if ( parent.attr( "title" ) ) {
                        parent.uniqueid();
                        that.parents[ this.id ] = {
                            element: this,
                            title: parent.attr( "title" )
                        };
                        parent.attr( "title", "" );
                    }
                });
            }

            this._updatecontent( target, event );
        },

        _updatecontent: function( target, event ) {
            var content,
                contentoption = this.options.content,
                that = this,
                eventtype = event ? event.type : null;

            if ( typeof contentoption === "string" ) {
                return this._open( event, target, contentoption );
            }

            content = contentoption.call( target[0], function( response ) {
                // ignore async response if tooltip was closed already
                if ( !target.data( "ui-tooltip-open" ) ) {
                    return;
                }
                // ie may instantly serve a cached response for ajax requests
                // delay this call to _open so the other call to _open runs first
                that._delay(function() {
                    // jquery creates a special event for focusin when it doesn't
                    // exist natively. to improve performance, the native event
                    // object is reused and the type is changed. therefore, we can't
                    // rely on the type being correct after the event finished
                    // bubbling, so we set it back to the previous value. (#8740)
                    if ( event ) {
                        event.type = eventtype;
                    }
                    this._open( event, target, response );
                });
            });
            if ( content ) {
                this._open( event, target, content );
            }
        },

        _open: function( event, target, content ) {
            var tooltipdata, tooltip, events, delayedshow, a11ycontent,
                positionoption = $.extend( {}, this.options.position );

            if ( !content ) {
                return;
            }

            // content can be updated multiple times. if the tooltip already
            // exists, then just update the content and bail.
            tooltipdata = this._find( target );
            if ( tooltipdata ) {
                tooltipdata.tooltip.find( ".ui-tooltip-content" ).html( content );
                return;
            }

            // if we have a title, clear it to prevent the native tooltip
            // we have to check first to avoid defining a title if none exists
            // (we don't want to cause an element to start matching [title])
            //
            // we use removeattr only for key events, to allow ie to export the correct
            // accessible attributes. for mouse events, set to empty string to avoid
            // native tooltip showing up (happens only when removing inside mouseover).
            if ( target.is( "[title]" ) ) {
                if ( event && event.type === "mouseover" ) {
                    target.attr( "title", "" );
                } else {
                    target.removeattr( "title" );
                }
            }

            tooltipdata = this._tooltip( target );
            tooltip = tooltipdata.tooltip;
            this._adddescribedby( target, tooltip.attr( "id" ) );
            tooltip.find( ".ui-tooltip-content" ).html( content );

            // support: voiceover on os x, jaws on ie <= 9
            // jaws announces deletions even when aria-relevant="additions"
            // voiceover will sometimes re-read the entire log region's contents from the beginning
            this.liveregion.children().hide();
            if ( content.clone ) {
                a11ycontent = content.clone();
                a11ycontent.removeattr( "id" ).find( "[id]" ).removeattr( "id" );
            } else {
                a11ycontent = content;
            }
            $( "<div>" ).html( a11ycontent ).appendto( this.liveregion );

            function position( event ) {
                positionoption.of = event;
                if ( tooltip.is( ":hidden" ) ) {
                    return;
                }
                tooltip.position( positionoption );
            }
            if ( this.options.track && event && /^mouse/.test( event.type ) ) {
                this._on( this.document, {
                    mousemove: position
                });
                // trigger once to override element-relative positioning
                position( event );
            } else {
                tooltip.position( $.extend({
                    of: target
                }, this.options.position ) );
            }

            tooltip.hide();

            this._show( tooltip, this.options.show );
            // handle tracking tooltips that are shown with a delay (#8644). as soon
            // as the tooltip is visible, position the tooltip using the most recent
            // event.
            if ( this.options.show && this.options.show.delay ) {
                delayedshow = this.delayedshow = setinterval(function() {
                    if ( tooltip.is( ":visible" ) ) {
                        position( positionoption.of );
                        clearinterval( delayedshow );
                    }
                }, $.fx.interval );
            }

            this._trigger( "open", event, { tooltip: tooltip } );

            events = {
                keyup: function( event ) {
                    if ( event.keycode === $.ui.keycode.escape ) {
                        var fakeevent = $.event(event);
                        fakeevent.currenttarget = target[0];
                        this.close( fakeevent, true );
                    }
                }
            };

            // only bind remove handler for delegated targets. non-delegated
            // tooltips will handle this in destroy.
            if ( target[ 0 ] !== this.element[ 0 ] ) {
                events.remove = function() {
                    this._removetooltip( tooltip );
                };
            }

            if ( !event || event.type === "mouseover" ) {
                events.mouseleave = "close";
            }
            if ( !event || event.type === "focusin" ) {
                events.focusout = "close";
            }
            this._on( true, target, events );
        },

        close: function( event ) {
            var tooltip,
                that = this,
                target = $( event ? event.currenttarget : this.element ),
                tooltipdata = this._find( target );

            // the tooltip may already be closed
            if ( !tooltipdata ) {
                return;
            }

            tooltip = tooltipdata.tooltip;

            // disabling closes the tooltip, so we need to track when we're closing
            // to avoid an infinite loop in case the tooltip becomes disabled on close
            if ( tooltipdata.closing ) {
                return;
            }

            // clear the interval for delayed tracking tooltips
            clearinterval( this.delayedshow );

            // only set title if we had one before (see comment in _open())
            // if the title attribute has changed since open(), don't restore
            if ( target.data( "ui-tooltip-title" ) && !target.attr( "title" ) ) {
                target.attr( "title", target.data( "ui-tooltip-title" ) );
            }

            this._removedescribedby( target );

            tooltipdata.hiding = true;
            tooltip.stop( true );
            this._hide( tooltip, this.options.hide, function() {
                that._removetooltip( $( this ) );
            });

            target.removedata( "ui-tooltip-open" );
            this._off( target, "mouseleave focusout keyup" );

            // remove 'remove' binding only on delegated targets
            if ( target[ 0 ] !== this.element[ 0 ] ) {
                this._off( target, "remove" );
            }
            this._off( this.document, "mousemove" );

            if ( event && event.type === "mouseleave" ) {
                $.each( this.parents, function( id, parent ) {
                    $( parent.element ).attr( "title", parent.title );
                    delete that.parents[ id ];
                });
            }

            tooltipdata.closing = true;
            this._trigger( "close", event, { tooltip: tooltip } );
            if ( !tooltipdata.hiding ) {
                tooltipdata.closing = false;
            }
        },

        _tooltip: function( element ) {
            var tooltip = $( "<div>" )
                    .attr( "role", "tooltip" )
                    .addclass( "ui-tooltip ui-widget ui-corner-all ui-widget-content " +
                        ( this.options.tooltipclass || "" ) ),
                id = tooltip.uniqueid().attr( "id" );

            $( "<div>" )
                .addclass( "ui-tooltip-content" )
                .appendto( tooltip );

            tooltip.appendto( this.document[0].body );

            return this.tooltips[ id ] = {
                element: element,
                tooltip: tooltip
            };
        },

        _find: function( target ) {
            var id = target.data( "ui-tooltip-id" );
            return id ? this.tooltips[ id ] : null;
        },

        _removetooltip: function( tooltip ) {
            tooltip.remove();
            delete this.tooltips[ tooltip.attr( "id" ) ];
        },

        _destroy: function() {
            var that = this;

            // close open tooltips
            $.each( this.tooltips, function( id, tooltipdata ) {
                // delegate to close method to handle common cleanup
                var event = $.event( "blur" ),
                    element = tooltipdata.element;
                event.target = event.currenttarget = element[ 0 ];
                that.close( event, true );

                // remove immediately; destroying an open tooltip doesn't use the
                // hide animation
                $( "#" + id ).remove();

                // restore the title
                if ( element.data( "ui-tooltip-title" ) ) {
                    // if the title attribute has changed since open(), don't restore
                    if ( !element.attr( "title" ) ) {
                        element.attr( "title", element.data( "ui-tooltip-title" ) );
                    }
                    element.removedata( "ui-tooltip-title" );
                }
            });
            this.liveregion.remove();
        }
    });



}));