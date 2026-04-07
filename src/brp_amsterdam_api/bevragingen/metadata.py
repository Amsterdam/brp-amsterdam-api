from rest_framework.metadata import BaseMetadata


class CustomMetadata(BaseMetadata):
    def determine_metadata(self, request, view):
        return {
            "renders": [renderer.media_type for renderer in view.renderer_classes],
            "parses": [parser.media_type for parser in view.parser_classes],
        }
