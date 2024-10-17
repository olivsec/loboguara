$(document).ready(function() {
    $('#certModal').on('show.bs.modal', function(event) {
        var button = $(event.relatedTarget); 
        var certData = button.data('cert'); 
        var modal = $(this);
        modal.find('#certData').text(JSON.stringify(certData, null, 2));
    });
});
