package socketsleuth.intruder.payloads.payloads;

import socketsleuth.intruder.payloads.models.IPayloadModel;

import javax.swing.*;

public interface IIntruderPayloadType {
    IPayloadModel getPayloadModel();
    JPanel getContainer();
}
