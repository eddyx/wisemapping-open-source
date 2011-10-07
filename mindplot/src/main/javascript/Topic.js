/*
 *    Copyright [2011] [wisemapping]
 *
 *   Licensed under WiseMapping Public License, Version 1.0 (the "License").
 *   It is basically the Apache License, Version 2.0 (the "License") plus the
 *   "powered by wisemapping" text requirement on every single page;
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the license at
 *
 *       http://www.wisemapping.org/license
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */


mindplot.Topic = new Class({
    Extends:mindplot.NodeGraph,
    initialize : function(model) {
        this.parent(model);
        this._textEditor = new mindplot.MultilineTextEditor(this);

        this._children = [];
        this._parent = null;
        this._relationships = [];
        this._isInWorkspace = false;
        this._helpers = [];
        this._buildShape();

        // Position a topic ....
        var pos = model.getPosition();
        if (pos != null && model.getType() == mindplot.model.INodeModel.CENTRAL_TOPIC_TYPE) {
            this.setPosition(pos);
        }

        // Register events for the topic ...
        this._registerEvents();
    },

    _registerEvents : function() {

        this.setMouseEventsEnabled(true);

        // Prevent click on the topics being propagated ...
        this.addEvent('click', function(event) {
            event.stopPropagation();
        });

        this.addEvent('dblclick', function (event) {
            this._textEditor.show();
            event.stopPropagation(true);
        }.bind(this));

        this._textEditor.addEvent('input', function(event, text) {
            var textShape = this.getTextShape();
//            var oldText = textShape.getText();

//            this._setText(text, false);
            // @Todo: I must resize, no change the position ...
//            textShape.setText(oldText);
        }.bind(this));

    },

    setShapeType : function(type) {
        this._setShapeType(type, true);

    },

    getParent : function() {
        return this._parent;
    },

    _setShapeType : function(type, updateModel) {
        // Remove inner shape figure ...
        var model = this.getModel();
        if ($defined(updateModel) && updateModel) {
            model.setShapeType(type);
        }

        var oldInnerShape = this.getInnerShape();
        if (oldInnerShape != null) {

            this._removeInnerShape();

            // Create a new one ...
            var innerShape = this.getInnerShape();

            // Update figure size ...
            var size = model.getSize();
            this.setSize(size, true);

            var group = this.get2DElement();
            group.appendChild(innerShape);

            // Move text to the front ...
            var text = this.getTextShape();
            text.moveToFront();

            //Move iconGroup to front ...
            var iconGroup = this.getIconGroup();
            if ($defined(iconGroup)) {
                iconGroup.moveToFront();
            }
            //Move connector to front
            var connector = this.getShrinkConnector();
            if ($defined(connector)) {
                connector.moveToFront();
            }

            //Move helpers to front
            this._helpers.forEach(function(helper) {
                helper.moveToFront();
            });

        }

    },

    getShapeType : function() {
        var model = this.getModel();
        var result = model.getShapeType();
        if (!$defined(result)) {
            result = this._defaultShapeType();
        }
        return result;
    },

    _removeInnerShape : function() {
        var group = this.get2DElement();
        var innerShape = this.getInnerShape();
        group.removeChild(innerShape);
        this._innerShape = null;
        return innerShape;
    },

    getInnerShape : function() {
        if (!$defined(this._innerShape)) {
            // Create inner box.
            this._innerShape = this.buildShape(mindplot.Topic.INNER_RECT_ATTRIBUTES);

            // Update bgcolor ...
            var bgColor = this.getBackgroundColor();
            this._setBackgroundColor(bgColor, false);

            // Update border color ...
            var brColor = this.getBorderColor();
            this._setBorderColor(brColor, false);

            // Define the pointer ...
            if (this.getType() != mindplot.model.INodeModel.CENTRAL_TOPIC_TYPE) {
                this._innerShape.setCursor('move');
            } else {
                this._innerShape.setCursor('default');
            }

        }
        return this._innerShape;
    },

    buildShape : function(attributes, type) {
        var result;
        if (!$defined(type)) {
            type = this.getShapeType();
        }

        if (type == mindplot.model.INodeModel.SHAPE_TYPE_RECT) {
            result = new web2d.Rect(0, attributes);
        }
        else if (type == mindplot.model.INodeModel.SHAPE_TYPE_ELIPSE) {
            result = new web2d.Rect(0.9, attributes);
        }
        else if (type == mindplot.model.INodeModel.SHAPE_TYPE_ROUNDED_RECT) {
            result = new web2d.Rect(0.3, attributes);
        }
        else if (type == mindplot.model.INodeModel.SHAPE_TYPE_LINE) {
            result = new web2d.Line({strokeColor:"#495879",strokeWidth:1, strokeOpacity:1});
            result.setSize = function(width, height) {
                this.size = {width:width, height:height};
                result.setFrom(-1, height);
                result.setTo(width + 1, height);

                // Lines will have the same color of the default connection lines...
                var stokeColor = mindplot.ConnectionLine.getStrokeColor();
                result.setStroke(1, 'solid', stokeColor);
            };

            result.getSize = function() {
                return this.size;
            };

            result.setPosition = function() {
            };

            var setStrokeFunction = result.setStroke;
            result.setFill = function(color) {

            };

            result.setStroke = function(color) {

            };
        }
        else {
            $assert(false, "Unsupported figure type:" + type);
        }

        result.setPosition(0, 0);
        return result;
    },


    setCursor : function(type) {
        var innerShape = this.getInnerShape();
        innerShape.setCursor(type);

        var outerShape = this.getOuterShape();
        outerShape.setCursor(type);

        var textShape = this.getTextShape();
        textShape.setCursor(type);
    },

    getOuterShape : function() {
        if (!$defined(this._outerShape)) {
            var rect = this.buildShape(mindplot.Topic.OUTER_SHAPE_ATTRIBUTES, mindplot.model.INodeModel.SHAPE_TYPE_ROUNDED_RECT);
            rect.setPosition(-2, -3);
            rect.setOpacity(0);
            this._outerShape = rect;
        }

        return this._outerShape;
    },

    getTextShape : function() {
        if (!$defined(this._text)) {
            this._text = this._buildTextShape(false);

            // Set Text ...
            var text = this.getText();
            this._setText(text, false);
        }
        return this._text;
    },

    getOrBuildIconGroup : function() {
        if (!$defined(this._iconsGroup)) {
            this._iconsGroup = this._buildIconGroup();
            var group = this.get2DElement();
            group.appendChild(this._iconsGroup.getNativeElement());
            this._iconsGroup.moveToFront();
        }
        return this._iconsGroup;
    },

    getIconGroup : function() {
        return this._iconsGroup;
    },

    _buildIconGroup : function() {
        var textHeight = this.getTextShape().getFontHeight();
        var result = new mindplot.IconGroup(this.getId(), textHeight);
        var padding = this._getInnerPadding();
        result.setPosition(padding, padding);

        var model = this.getModel();

        //Icons
        var icons = model.getIcons();
        for (var i = 0; i < icons.length; i++) {
            // Update model identifier ...
            var iconModel = icons[i];
            var icon = new mindplot.ImageIcon(this, iconModel);
            result.addIcon(icon, true);
        }

        //Links
        var links = model.getLinks();
        for (var i = 0; i < links.length; i++) {
            this._hasLink = true;
            this._link = new mindplot.LinkIcon(links[i], this, designer);
            result.addIcon(this._link);
        }

        //Notes
        var notes = model.getNotes();
        for (var j = 0; j < notes.length; j++) {
            this._hasNote = true;
            this._note = new mindplot.Note(this, notes[j]);
            result.addIcon(this._note);
        }

        return result;
    },

    addLink : function(url, designer) {
        var iconGroup = this.getOrBuildIconGroup();
        var model = this.getModel();
        var linkModel = model.createLink(url);
        model.addLink(linkModel);
        this._link = new mindplot.LinkIcon(linkModel, this, designer);
        iconGroup.addIcon(this._link);
        this._hasLink = true;
        this._adjustShapes();
    },

    addNote : function(text) {
        var iconGroup = this.getOrBuildIconGroup();
        var model = this.getModel();

        var noteModel = model.createNote(text);
        model.addNote(noteModel);

        this._note = new mindplot.Note(this, noteModel);
        iconGroup.addIcon(this._note);
        this._hasNote = true;
        this._adjustShapes();
    },

    addIcon : function(iconType) {
        var iconGroup = this.getOrBuildIconGroup();
        var model = this.getModel();

        // Update model ...
        var iconModel = model.createIcon(iconType);
        model.addIcon(iconModel);

        var imageIcon = new mindplot.ImageIcon(this, iconModel);
        iconGroup.addIcon(imageIcon,true);
        this._adjustShapes();
        return imageIcon;
    },

    removeIcon : function(iconModel) {

        //Removing the icon from MODEL
        var model = this.getModel();
        model.removeIcon(iconModel);

        //Removing the icon from UI
        var iconGroup = this.getIconGroup();
        if ($defined(iconGroup)) {
            iconGroup.removeIcon(iconModel);
        }
        this._adjustShapes();
    },

    removeLink : function() {
        var model = this.getModel();
        var links = model.getLinks();
        model._removeLink(links[0]);
        var iconGroup = this.getIconGroup();
        if ($defined(iconGroup)) {
            iconGroup.removeIcon(mindplot.LinkIcon.IMAGE_URL);
            if (iconGroup.getIcons().length == 0) {
                this.get2DElement().removeChild(iconGroup.getNativeElement());
                this._iconsGroup = null;
            }
        }
        this._link = null;
        this._hasLink = false;
        this._adjustShapes();
    },

    removeNote : function() {
        // Update model ...
        var model = this.getModel();
        var notes = model.getNotes();
        model.removeNote(notes[0]);

        // Remove UI ...
        var iconGroup = this.getIconGroup();
        if ($defined(iconGroup)) {
            iconGroup.removeIconByUrl(mindplot.Note.IMAGE_URL);
        }

        this._note = null;
        this._hasNote = false;
        this._adjustShapes();
    },

    hasNote : function() {
        return this._hasNote;
    },

    addRelationship : function(relationship) {
        this._relationships.push(relationship);
    },

    removeRelationship : function(relationship) {
        this._relationships.erase(relationship);
    },

    getRelationships : function() {
        return this._relationships;
    },

    _buildTextShape : function(disableEventsListeners) {
        var result = new web2d.Text();
        var family = this.getFontFamily();
        var size = this.getFontSize();
        var weight = this.getFontWeight();
        var style = this.getFontStyle();
        result.setFont(family, size, style, weight);

        var color = this.getFontColor();
        result.setColor(color);

        if (!disableEventsListeners) {
            // Propagate mouse events ...
            if (this.getType() != mindplot.model.INodeModel.CENTRAL_TOPIC_TYPE) {
                result.setCursor('move');
            } else {
                result.setCursor('default');
            }
        }

        return result;
    },

    _getInnerPadding : function() {
        throw "this must be implemented";
    },

    setFontFamily : function(value, updateModel) {
        var textShape = this.getTextShape();
        textShape.setFontFamily(value);
        if ($defined(updateModel) && updateModel) {
            var model = this.getModel();
            model.setFontFamily(value);
        }
        this._adjustShapes(updateModel);
    },

    setFontSize : function(value, updateModel) {

        var textShape = this.getTextShape();
        textShape.setSize(value);

        if ($defined(updateModel) && updateModel) {
            var model = this.getModel();
            model.setFontSize(value);
        }
        this._adjustShapes(updateModel);

    },

    setFontStyle : function(value, updateModel) {
        var textShape = this.getTextShape();
        textShape.setStyle(value);
        if ($defined(updateModel) && updateModel) {
            var model = this.getModel();
            model.setFontStyle(value);
        }
        this._adjustShapes(updateModel);
    },

    setFontWeight : function(value, updateModel) {
        var textShape = this.getTextShape();
        textShape.setWeight(value);
        if ($defined(updateModel) && updateModel) {
            var model = this.getModel();
            model.setFontWeight(value);
        }
    },

    getFontWeight : function() {
        var model = this.getModel();
        var result = model.getFontWeight();
        if (!$defined(result)) {
            var font = this._defaultFontStyle();
            result = font.weight;
        }
        return result;
    },

    getFontFamily : function() {
        var model = this.getModel();
        var result = model.getFontFamily();
        if (!$defined(result)) {
            var font = this._defaultFontStyle();
            result = font.font;
        }
        return result;
    },

    getFontColor : function() {
        var model = this.getModel();
        var result = model.getFontColor();
        if (!$defined(result)) {
            var font = this._defaultFontStyle();
            result = font.color;
        }
        return result;
    },

    getFontStyle : function() {
        var model = this.getModel();
        var result = model.getFontStyle();
        if (!$defined(result)) {
            var font = this._defaultFontStyle();
            result = font.style;
        }
        return result;
    },

    getFontSize : function() {
        var model = this.getModel();
        var result = model.getFontSize();
        if (!$defined(result)) {
            var font = this._defaultFontStyle();
            result = font.size;
        }
        return result;
    },

    setFontColor : function(value, updateModel) {
        var textShape = this.getTextShape();
        textShape.setColor(value);
        if ($defined(updateModel) && updateModel) {
            var model = this.getModel();
            model.setFontColor(value);
        }
    },

    _setText : function(text, updateModel) {
        var textShape = this.getTextShape();
        textShape.setText(text);

        if ($defined(updateModel) && updateModel) {
            var model = this.getModel();
            model.setText(text);
        }
        this._adjustShapes(updateModel);
    },

    setText : function(text) {
        this._setText(text, true);
    },

    getText : function() {
        var model = this.getModel();
        var result = model.getText();
        if (!$defined(result)) {
            result = this._defaultText();
        }
        return result;
    },

    setBackgroundColor : function(color) {
        this._setBackgroundColor(color, true);
    },

    _setBackgroundColor : function(color, updateModel) {
        var innerShape = this.getInnerShape();
        innerShape.setFill(color);

        var connector = this.getShrinkConnector();
        connector.setFill(color);
        if ($defined(updateModel) && updateModel) {
            var model = this.getModel();
            model.setBackgroundColor(color);
        }
    },

    getBackgroundColor : function() {
        var model = this.getModel();
        var result = model.getBackgroundColor();
        if (!$defined(result)) {
            result = this._defaultBackgroundColor();
        }
        return result;
    },

    setBorderColor : function(color) {
        this._setBorderColor(color, true);
    },

    _setBorderColor : function(color, updateModel) {
        var innerShape = this.getInnerShape();
        innerShape.setAttribute('strokeColor', color);

        var connector = this.getShrinkConnector();
        connector.setAttribute('strokeColor', color);


        if ($defined(updateModel) && updateModel) {
            var model = this.getModel();
            model.setBorderColor(color);
        }
    },

    getBorderColor : function() {
        var model = this.getModel();
        var result = model.getBorderColor();
        if (!$defined(result)) {
            result = this._defaultBorderColor();
        }
        return result;
    },

    _buildShape : function() {
        var groupAttributes = {width: 100, height:100,coordSizeWidth:100,coordSizeHeight:100};
        var group = new web2d.Group(groupAttributes);
        this._set2DElement(group);

        // Shape must be build based on the model width ...
        var outerShape = this.getOuterShape();
        var innerShape = this.getInnerShape();
        var textShape = this.getTextShape();
        var shrinkConnector = this.getShrinkConnector();

        // Add to the group ...
        group.appendChild(outerShape);
        group.appendChild(innerShape);
        group.appendChild(textShape);

        // Update figure size ...
        var model = this.getModel();
        if (model.getLinks().length != 0 || model.getNotes().length != 0 || model.getIcons().length != 0) {
            this.getOrBuildIconGroup();
        }

        if (this.getType() != mindplot.model.INodeModel.CENTRAL_TOPIC_TYPE) {
            shrinkConnector.addToWorkspace(group);
        }

        // Register listeners ...
        this._registerDefaultListenersToElement(group, this);

        // Put all the topic elements in place ...
        this._adjustShapes(false);
    },

    _registerDefaultListenersToElement : function(elem, topic) {
        var mouseOver = function(event) {
            if (topic.isMouseEventsEnabled()) {
                topic.handleMouseOver(event);
            }
        };
        elem.addEvent('mouseover', mouseOver);

        var outout = function(event) {
            if (topic.isMouseEventsEnabled()) {
                topic.handleMouseOut(event);
            }
        };
        elem.addEvent('mouseout', outout);

        // Focus events ...
        var mouseDown = function(event) {
            var value = true;
            if ((event.metaKey && Browser.Platform.mac) || (event.ctrlKey && !Browser.Platform.mac)) {
                value = !this.isOnFocus();
                event.stopPropagation();
                event.preventDefault();
            }
            topic.setOnFocus(value);
        }.bind(this);
        elem.addEvent('mousedown', mouseDown);
    },

    areChildrenShrinked : function() {
        var model = this.getModel();
        return model.areChildrenShrinked();
    },

    isCollapsed : function() {
        var model = this.getModel();
        var result = false;

        var current = this.getParent();
        while (current && !result) {
            result = current.areChildrenShrinked();
            current = current.getParent();
        }
        return result;
    },

    setChildrenShrinked : function(value) {
        // Update Model ...
        var model = this.getModel();
        model.setChildrenShrinked(value);

        // Change render base on the state.
        var shrinkConnector = this.getShrinkConnector();
        shrinkConnector.changeRender(value);

        // Hide children ...
        core.Utils.setChildrenVisibilityAnimated(this, !value);
        mindplot.EventBus.instance.fireEvent(mindplot.EventBus.events.NodeShrinkEvent, [this]);
    },

    getShrinkConnector : function() {
        var result = this._connector;
        if (this._connector == null) {
            this._connector = new mindplot.ShirinkConnector(this);
            this._connector.setVisibility(false);
            result = this._connector;

        }
        return result;
    },

    handleMouseOver : function() {
        var outerShape = this.getOuterShape();
        outerShape.setOpacity(1);
        mindplot.EventBus.instance.fireEvent(mindplot.EventBus.events.NodeMouseOverEvent, [this]);
    },

    handleMouseOut : function(event) {
        var outerShape = this.getOuterShape();
        if (!this.isOnFocus()) {
            outerShape.setOpacity(0);
        }
        mindplot.EventBus.instance.fireEvent(mindplot.EventBus.events.NodeMouseOutEvent, [this]);
    },

    showTextEditor : function(text) {
        this._textEditor.show(text);
    },

    showNoteEditor : function() {

        var topicId = this.getId();
        var model = this.getModel();
        var editorModel = {
            getValue : function() {
                var notes = model.getNotes();
                var result;
                if (notes.length > 0)
                    result = notes[0].getText();

                return result;
            },

            setValue : function(value) {
                var dispatcher = mindplot.ActionDispatcher.getInstance();
                if (!$defined(value)) {
                    dispatcher.removeNoteFromTopic(topicId);
                }
                else {
                    dispatcher.changeNoteToTopic(topicId, value);
                }
            }
        };

        this.closeEditors();
        var editor = new mindplot.widget.NoteEditor(editorModel);
        editor.show();
    },

    closeEditors : function() {
        this._textEditor.close(true);
    },

    /**
     * Point: references the center of the rect shape.!!!
     */
    setPosition : function(point) {
        // Elements are positioned in the center.
        // All topic element must be positioned based on the innerShape.
        var size = this.getSize();

        var cx = Math.round(point.x - (size.width / 2));
        var cy = Math.round(point.y - (size.height / 2));

        // Update visual position.
        this._elem2d.setPosition(cx, cy);

        // Update model's position ...
        var model = this.getModel();
        model.setPosition(point.x, point.y);

        // Update connection lines ...
        this._updateConnectionLines();

        // Check object state.
        this.invariant();
    },

    getOutgoingLine : function() {
        return this._outgoingLine;
    },

    getIncomingLines : function() {
        var result = [];
        var children = this._getChildren();
        for (var i = 0; i < children.length; i++) {
            var node = children[i];
            var line = node.getOutgoingLine();
            if ($defined(line)) {
                result.push(line);
            }
        }
        return result;
    },

    getOutgoingConnectedTopic : function() {
        var result = null;
        var line = this.getOutgoingLine();
        if ($defined(line)) {
            result = line.getTargetTopic();
        }
        return result;
    },


    _updateConnectionLines : function() {
        // Update this to parent line ...
        var outgoingLine = this.getOutgoingLine();
        if ($defined(outgoingLine)) {
            outgoingLine.redraw();
        }

        // Update all the incoming lines ...
        var incomingLines = this.getIncomingLines();
        for (var i = 0; i < incomingLines.length; i++) {
            incomingLines[i].redraw();
        }

        // Update relationship lines
        for (var j = 0; j < this._relationships.length; j++) {
            this._relationships[j].redraw();
        }
    },

    setBranchVisibility : function(value) {
        var current = this;
        var parent = this;
        while (parent != null && parent.getType() != mindplot.model.INodeModel.CENTRAL_TOPIC_TYPE) {
            current = parent;
            parent = current.getParent();
        }
        current.setVisibility(value);
    },


    setVisibility : function(value) {
        this._setTopicVisibility(value);

        // Hide all children...
        this._setChildrenVisibility(value);

        this._setRelationshipLinesVisibility(value);
    },

    moveToBack : function() {

        // Update relationship lines
        for (var j = 0; j < this._relationships.length; j++) {
            this._relationships[j].moveToBack();
        }
        var connector = this.getShrinkConnector();
        if ($defined(connector)) {
            connector.moveToBack();
        }

        this.get2DElement().moveToBack();
    },

    moveToFront : function() {

        this.get2DElement().moveToFront();
        var connector = this.getShrinkConnector();
        if ($defined(connector)) {
            connector.moveToFront();
        }
        // Update relationship lines
        for (var j = 0; j < this._relationships.length; j++) {
            this._relationships[j].moveToFront();
        }
    },

    isVisible : function() {
        var elem = this.get2DElement();
        return elem.isVisible();
    },

    _setRelationshipLinesVisibility : function(value) {
        this._relationships.forEach(function(relationship) {
            relationship.setVisibility(value);
        });
    },

    _setTopicVisibility : function(value) {
        var elem = this.get2DElement();
        elem.setVisibility(value);

        if (this.getIncomingLines().length > 0) {
            var connector = this.getShrinkConnector();
            connector.setVisibility(value);
        }

        var textShape = this.getTextShape();
        textShape.setVisibility(value);

    },

    setOpacity : function(opacity) {
        var elem = this.get2DElement();
        elem.setOpacity(opacity);

        this.getShrinkConnector().setOpacity(opacity);

        var textShape = this.getTextShape();
        textShape.setOpacity(opacity);
    },

    _setChildrenVisibility : function(isVisible) {

        // Hide all children.
        var children = this._getChildren();
        var model = this.getModel();

        isVisible = isVisible ? !model.areChildrenShrinked() : isVisible;
        for (var i = 0; i < children.length; i++) {
            var child = children[i];
            child.setVisibility(isVisible);

            var outgoingLine = child.getOutgoingLine();
            outgoingLine.setVisibility(isVisible);
        }

    },

    invariant : function() {
        var line = this._outgoingLine;
        var model = this.getModel();
        var isConnected = model.isConnected();

        // Check consistency...
        if ((isConnected && !line) || (!isConnected && line)) {
            // $assert(false,'Illegal state exception.');
        }
    },


    _setSize : function(size) {
        $assert(size, "size can not be null");
        $assert($defined(size.width), "size seem not to be a valid element");

        mindplot.NodeGraph.prototype.setSize.call(this, size);

        var outerShape = this.getOuterShape();
        var innerShape = this.getInnerShape();

        outerShape.setSize(size.width + 4, size.height + 6);
        innerShape.setSize(size.width, size.height);
    },

    setSize : function(size, force, updatePosition) {
        var oldSize = this.getSize();
        if (oldSize.width != size.width || oldSize.height != size.height || force) {
            this._setSize(size);

            // Update the figure position(ej: central topic must be centered) and children position.
            this._updatePositionOnChangeSize(oldSize, size, updatePosition);

            mindplot.EventBus.instance.fireEvent(mindplot.EventBus.events.NodeResizeEvent, [this]);

        }
    },

    _updatePositionOnChangeSize : function(oldSize, newSize, updatePosition) {
        $assert(false, "this method must be overided");
    },

    disconnect : function(workspace) {
        var outgoingLine = this.getOutgoingLine();
        if ($defined(outgoingLine)) {
            $assert(workspace, 'workspace can not be null');

            this._outgoingLine = null;

            // Disconnect nodes ...
            var targetTopic = outgoingLine.getTargetTopic();
            targetTopic.removeChild(this);

            // Update model ...
            var childModel = this.getModel();
            childModel.disconnect();

            this._parent = null;

            // Remove graphical element from the workspace...
            outgoingLine.removeFromWorkspace(workspace);

            // Remove from workspace.
            mindplot.EventBus.instance.fireEvent(mindplot.EventBus.events.NodeDisconnectEvent, [targetTopic, this]);

            // Change text based on the current connection ...
            var model = this.getModel();
            if (!model.getText()) {
                var text = this.getText();
                this._setText(text, false);
            }
            if (!model.getFontSize()) {
                var size = this.getFontSize();
                this.setFontSize(size, false);
            }

            // Hide connection line?.
            if (targetTopic._getChildren().length == 0) {
                var connector = targetTopic.getShrinkConnector();
                connector.setVisibility(false);
            }

        }
    },

    getOrder : function() {
        var model = this.getModel();
        return model.getOrder();
    },

    setOrder : function(value) {
        var model = this.getModel();
        model.setOrder(value);
    },

    connectTo : function(targetTopic, workspace, isVisible) {
        $assert(!this._outgoingLine, 'Could not connect an already connected node');
        $assert(targetTopic != this, 'Cilcular connection are not allowed');
        $assert(targetTopic, 'Parent Graph can not be null');
        $assert(workspace, 'Workspace can not be null');

        // Connect Graphical Nodes ...
        targetTopic.appendChild(this);
        this._parent = targetTopic;

        // Update model ...
        var targetModel = targetTopic.getModel();
        var childModel = this.getModel();
        childModel.connectTo(targetModel);

        // Update topic position based on the state ...
        mindplot.EventBus.instance.fireEvent(mindplot.EventBus.events.NodeConnectEvent, [targetTopic, this]);

        // Create a connection line ...
        var outgoingLine = new mindplot.ConnectionLine(this, targetTopic);
        if ($defined(isVisible))
            outgoingLine.setVisibility(isVisible);
        this._outgoingLine = outgoingLine;
        workspace.appendChild(outgoingLine);

        // Update figure is necessary.
        this.updateTopicShape(targetTopic);

        // Change text based on the current connection ...
        var model = this.getModel();
        if (!model.getText()) {
            var text = this.getText();
            this._setText(text, false);
        }
        if (!model.getFontSize()) {
            var size = this.getFontSize();
            this.setFontSize(size, false);
        }
        var textShape = this.getTextShape();

        // Display connection node...
        var connector = targetTopic.getShrinkConnector();
        connector.setVisibility(true);

        // Redraw line ...
        outgoingLine.redraw();
    },

    appendChild : function(child) {
        var children = this._getChildren();
        children.push(child);
    },

    removeChild : function(child) {
        var children = this._getChildren();
        children.erase(child);
    },

    _getChildren : function() {
        var result = this._children;
        if (!$defined(result)) {
            this._children = [];
            result = this._children;
        }
        return result;
    },

    removeFromWorkspace : function(workspace) {
        var elem2d = this.get2DElement();
        workspace.removeChild(elem2d);
        var line = this.getOutgoingLine();
        if ($defined(line)) {
            workspace.removeChild(line);
        }
        this._isInWorkspace = false;
    },

    addToWorkspace : function(workspace) {
        var elem = this.get2DElement();
        workspace.appendChild(elem);
        this._isInWorkspace = true;
    },

    isInWorkspace : function() {
        return this._isInWorkspace;
    },

    createDragNode : function() {
        var result = this.parent();

        // Is the node already connected ?
        var targetTopic = this.getOutgoingConnectedTopic();
        if ($defined(targetTopic)) {
            result.connectTo(targetTopic);
        }

        // If a drag node is create for it, let's hide the editor.
        this._textEditor.close();

        return result;
    },

    _adjustShapes : function(updatePosition) {
        (function() {
            var textShape = this.getTextShape();
            var textWidth = textShape.getWidth();

            var textHeight = textShape.getHeight();
            textHeight = textHeight != 0 ? textHeight : 20;

            var topicPadding = this._getInnerPadding();

            // Adjust the icon size to the size of the text ...
            var iconGroup = this.getOrBuildIconGroup();
            var fontHeight = this.getTextShape().getFontHeight();
            iconGroup.setPosition(topicPadding, topicPadding);
            iconGroup.seIconSize(fontHeight, fontHeight);

            // Add a extra padding between the text and the icons
            var iconsWidth = iconGroup.getSize().width;
            if (iconsWidth != 0) {

                iconsWidth = iconsWidth + (textHeight / 4);
            }

            var height = textHeight + (topicPadding * 2);
            var width = textWidth + iconsWidth + (topicPadding * 2);

            var size = {width:width,height:height};
            this.setSize(size, false, updatePosition);

            // Position node ...
            textShape.setPosition(topicPadding + iconsWidth, topicPadding);
        }).delay(0, this);
    },

    addHelper : function(helper) {
        helper.addToGroup(this.get2DElement());
        this._helpers.push(helper);
    }

});


mindplot.Topic.CONNECTOR_WIDTH = 6;
mindplot.Topic.OUTER_SHAPE_ATTRIBUTES = {fillColor:'#dbe2e6',stroke:'1 solid #77555a',x:0,y:0};
mindplot.Topic.INNER_RECT_ATTRIBUTES = {stroke:'0.5 solid'};
